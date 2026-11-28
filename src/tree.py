"""Common policy-tree format, validation, and tree utilities.

Each node is a dictionary of policy-table columns plus a children list. Database
IDs and parent IDs are assigned on insertion. OR with no children is empty/false;
AND with no children is universal/true. NOT always has exactly one child.

Persistence lives in ``postgres.store`` and ``postgres.export``; the CLI is in
``cli``.
"""

from copy import deepcopy
import json


COLUMNS = ('name', 'display_name', 'comment', 'provider', 'provider_detail',
           'operator_onChildren', 'condition_raw', 'condition_cel', 'condition_json',
           'condition_raw_type', 'child_position')
OPERATORS = {'AND', 'OR', 'NOT'}


def make_node(name, provider, provider_detail, operator_onChildren='AND', *, children=None,
              condition_json=None, condition_raw=None, condition_cel=None,
              display_name=None, comment=None, condition_raw_type=None,
              child_position=None):
    """Construct a node using only column names from db/policy.sql."""
    return dict(name=name, display_name=display_name, comment=comment,
                provider=provider, provider_detail=provider_detail,
                operator_onChildren=operator_onChildren, condition_raw=condition_raw,
                condition_cel=condition_cel, condition_json=condition_json,
                condition_raw_type=condition_raw_type or ('json' if condition_json is not None else None),
                child_position=child_position,
                children=list(children) if children is not None else [])


def validate_tree(tree, *, check_source=True):
    """Reject invalid or cyclic trees before any database writes occur.

    ``check_source=False`` keeps the structural checks but skips the
    condition_raw/condition_json agreement, so a tree edited in memory can still
    be read or emitted. Writes keep the default (strict) behaviour.
    """
    seen = set()

    def visit(node, path='root'):
        def fail(message):
            raise ValueError(f'{path}: {message}')

        if not isinstance(node, dict):
            fail('Every policy node must be a dictionary')
        if id(node) in seen:
            fail('Policy nodes cannot be cyclic or shared between parents')
        seen.add(id(node))
        unknown = set(node) - set(COLUMNS) - {'children'}
        if unknown:
            fail(f'Unknown policy fields: {sorted(unknown)}')
        if node.get('operator_onChildren') not in OPERATORS:
            fail('Policy operator must be AND, OR, or NOT')
        position = node.get('child_position')
        if position is not None and (type(position) is not int or position < 0):
            fail('child_position must be a nonnegative integer or None')
        for key in COLUMNS:
            if key not in ('condition_json', 'child_position') and node.get(key) is not None:
                if not isinstance(node[key], str):
                    fail(f'{key} must be text or None')
        children = node.get('children', [])
        if not isinstance(children, list):
            fail('children must be a list')
        if node['operator_onChildren'] == 'NOT' and len(children) != 1:
            fail('NOT requires exactly one child')
        if children and any(node.get(key) is not None for key in
                            ('condition_json', 'condition_cel')):
            fail('Expression nodes must be leaves; use a parent to combine them')
        try:
            json.dumps(node.get('condition_json'), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(f'{path}: condition_json must be JSON serializable') from exc
        if (check_source and node.get('condition_json') is not None
                and node.get('condition_raw') is not None):
            from .conditions.source import normalize_condition
            normalize_condition(node['condition_json'], node['condition_raw'],
                                node.get('condition_raw_type'))
        for index, child in enumerate(children):
            visit(child, f'{path}/children[{index}]')

    visit(tree)


def _has_expression(node):
    return (node.get('condition_json') is not None or node.get('condition_cel') is not None
            or (node.get('condition_raw') is not None and not node.get('children')))


def _marked(node):
    return node.get('child_position') is not None


def _can_remove_group(node):
    return not _has_expression(node) and not _marked(node)


def _constant(node):
    if (_marked(node) or node.get('children') or node.get('condition_raw') is not None
            or node.get('condition_json') is not None):
        return None
    cel = node.get('condition_cel')
    if cel in ('true', 'false'):
        return cel == 'true'
    if cel is None and node['operator_onChildren'] in ('AND', 'OR'):
        return node['operator_onChildren'] == 'AND'
    return None


def _set_constant(node, value):
    node['operator_onChildren'] = 'AND' if value else 'OR'
    node['children'] = []
    return node


def _predicate_key(node):
    if _marked(node):
        return None
    children = tuple(_predicate_key(child) for child in node.get('children', []))
    if None in children:
        return None
    expression = node.get('condition_json')
    try:
        condition = json.dumps(expression, sort_keys=True)
    except TypeError:
        # A Python dictionary can contain a mix of JSON-coercible key types.
        condition = json.dumps(expression)
    return (node.get('provider'), node.get('provider_detail'), node['operator_onChildren'],
            node.get('condition_raw_type'), node.get('condition_raw'), condition,
            node.get('condition_cel'), children)


def _replace_group(node, replacement, *, is_root):
    if not is_root:
        return replacement
    context_changes = any(node.get(key) is not None and node.get(key) != replacement.get(key)
                          for key in ('provider', 'provider_detail'))
    if (_marked(replacement) or context_changes
            or (node.get('condition_raw') is not None and _has_expression(replacement))):
        # The root source and the leaf predicate need separate condition_raw fields.
        node['operator_onChildren'] = 'AND'
        node['children'] = [replacement]
        return node
    for key in ('name', 'display_name', 'comment'):
        if node.get(key) is not None:
            replacement[key] = node[key]
    if node.get('condition_raw') is not None:
        replacement['condition_raw'] = node['condition_raw']
        replacement['condition_raw_type'] = node.get('condition_raw_type')
    return replacement


def _reduce_group(node, operator):
    neutral = operator == 'AND'
    annihilator = not neutral
    children = []
    for child in node['children']:
        if _constant(child) is neutral:
            continue
        if (_can_remove_group(child) and child['operator_onChildren'] == operator
                and child.get('condition_raw') is None):
            children.extend(child['children'])
        else:
            children.append(child)

    unique = []
    seen = set()
    for child in children:
        key = _predicate_key(child)
        if key is not None:
            if key in seen:
                continue
            seen.add(key)
        unique.append((child, key))

    opposite = 'OR' if neutral else 'AND'
    kept = []
    negations = []
    can_discard = all(key is not None for _, key in unique)
    for child, key in unique:
        child_operator = child['operator_onChildren']
        if can_discard and _constant(child) is annihilator:
            return _set_constant(node, annihilator)
        if key is not None and _can_remove_group(child):
            if child_operator == 'NOT':
                if can_discard and _predicate_key(child['children'][0]) in seen:
                    return _set_constant(node, annihilator)
                negations.append(child)
            elif child_operator == opposite and any(
                    _predicate_key(grandchild) in seen for grandchild in child['children']):
                continue
        kept.append(child)

    if len(negations) >= 2:
        negation_ids = {id(child) for child in negations}
        group = make_node(None, node.get('provider'), node.get('provider_detail'), opposite,
                          children=[child['children'][0] for child in negations])
        combined = make_node(None, node.get('provider'), node.get('provider_detail'), 'NOT',
                             children=[group])
        kept = [combined if child is negations[0] else child
                for child in kept if child is negations[0] or id(child) not in negation_ids]
    node['children'] = kept
    return node


def canonicalize(tree):
    """Return a reduced copy, using Boolean identities over opaque predicates."""
    validate_tree(tree)
    reduced = deepcopy(tree)
    while True:
        size = _node_count(reduced)
        reduced = _canonical(reduced, is_root=True)
        if _node_count(reduced) == size:
            return reduced


def _node_count(node):
    return 1 + sum(_node_count(child) for child in node.get('children', []))


def _canonical(node, *, is_root):
    node['children'] = [_canonical(child, is_root=False)
                        for child in node.get('children', [])]
    if _has_expression(node):
        return node
    operator = node['operator_onChildren']
    if operator == 'NOT':
        child = node['children'][0]
        value = _constant(child)
        if value is not None:
            return _set_constant(node, not value)
        if _can_remove_group(node) and child['operator_onChildren'] == 'NOT' and _can_remove_group(child):
            return _replace_group(node, child['children'][0], is_root=is_root)
        return node

    node = _reduce_group(node, operator)
    if _can_remove_group(node) and len(node['children']) == 1:
        return _replace_group(node, node['children'][0], is_root=is_root)
    return node


def strip_database_ids(tree):
    """Return a copy of a database export without ``id`` and ``parent_id``.

    ``examples/generated/*.json`` are exports of stored trees: every node also
    carries the row's primary key and its parent's key. Those fields are not part
    of the tree schema, so an export must be stripped before it can be
    validated, compared with parser output, or re-imported.
    """
    node = {key: deepcopy(value) for key, value in tree.items()
            if key not in ('id', 'parent_id')}
    node['children'] = [strip_database_ids(child)
                        for child in tree.get('children', [])]
    return node
