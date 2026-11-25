"""Common policy-tree format, validation, and tree utilities.

Each node is a dictionary of policy-table columns plus a children list. Database
IDs and parent IDs are assigned on insertion. OR with no children is empty/false;
AND with no children is universal/true. NOT always has exactly one child.
SUBTRACT has two operands, identified by child positions 0 and 1.

Persistence lives in ``policyStore``, export in ``policyExport``, and the CLI in
``policyCli``; the wrappers below keep the historical imports working.
"""

from copy import deepcopy
import json


COLUMNS = ('name', 'display_name', 'comment', 'provider', 'provider_detail',
           'operator_onChildren', 'condition_raw', 'condition_cel', 'condition_json',
           'condition_raw_type', 'effect', 'child_position')
OPERATORS = {'AND', 'OR', 'NOT', 'SUBTRACT'}


def make_node(name, provider, provider_detail, operator_onChildren='AND', *, children=None,
              condition_json=None, condition_raw=None, condition_cel=None,
              display_name=None, comment=None, condition_raw_type=None,
              effect=None, child_position=None):
    """Construct a node using only column names from db/policy.sql."""
    return dict(name=name, display_name=display_name, comment=comment,
                provider=provider, provider_detail=provider_detail,
                operator_onChildren=operator_onChildren, condition_raw=condition_raw,
                condition_cel=condition_cel, condition_json=condition_json,
                condition_raw_type=condition_raw_type or ('json' if condition_json is not None else None),
                effect=effect, child_position=child_position,
                children=list(children) if children is not None else [])


def validate_tree(tree):
    """Reject invalid or cyclic trees before any database writes occur."""
    seen = set()

    def visit(node):
        if not isinstance(node, dict):
            raise ValueError('Every policy node must be a dictionary')
        if id(node) in seen:
            raise ValueError('Policy nodes cannot be cyclic or shared between parents')
        seen.add(id(node))
        unknown = set(node) - set(COLUMNS) - {'children'}
        if unknown:
            raise ValueError(f'Unknown policy fields: {sorted(unknown)}')
        if node.get('operator_onChildren') not in OPERATORS:
            raise ValueError('Policy operator must be AND, OR, NOT, or SUBTRACT')
        position = node.get('child_position')
        if position is not None and (type(position) is not int or position < 0):
            raise ValueError('child_position must be a nonnegative integer or None')
        for key in COLUMNS:
            if key not in ('condition_json', 'child_position') and node.get(key) is not None:
                if not isinstance(node[key], str):
                    raise ValueError(f'{key} must be text or None')
        children = node.get('children', [])
        if not isinstance(children, list):
            raise ValueError('children must be a list')
        if node['operator_onChildren'] == 'NOT' and len(children) != 1:
            raise ValueError('NOT requires exactly one child')
        if children and any(node.get(key) is not None for key in
                            ('condition_json', 'condition_cel')):
            raise ValueError('Expression nodes must be leaves; use a parent to combine them')
        try:
            json.dumps(node.get('condition_json'), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError('condition_json must be JSON serializable') from exc
        if node.get('condition_json') is not None and node.get('condition_raw') is not None:
            from .conditions.source import normalize_condition
            normalize_condition(node['condition_json'], node['condition_raw'], node.get('condition_raw_type'))
        for child in children:
            visit(child)
        if node['operator_onChildren'] == 'SUBTRACT' and (
                len(children) != 2 or {child.get('child_position') for child in children} != {0, 1}):
            raise ValueError('SUBTRACT requires two children with child_position 0 and 1')

    visit(tree)


# Compatibility imports: retain existing public APIs while implementations live
# in focused modules. Lazy wrappers avoid circular dependencies.
from .policyDocument import load_document


def insert_policy_tree(*args, **kwargs):
    from .postgres.store import insert_policy_tree as implementation
    return implementation(*args, **kwargs)


def write_policy_tree(*args, **kwargs):
    from .postgres.store import write_policy_tree as implementation
    return implementation(*args, **kwargs)


def run_cli(*args, **kwargs):
    from .policyCli import run_cli as implementation
    return implementation(*args, **kwargs)


def _has_expression(node):
    return node.get('condition_json') is not None or node.get('condition_cel') is not None


def _can_remove_group(node):
    return (not _has_expression(node) and node.get('effect') is None
            and node.get('child_position') is None)


def canonicalize(tree):
    """Return a meaning-preserving reduced copy of a validated policy tree.

    Only structural nodes are rewritten: a grouping node carries no expression,
    so replacing it with its children cannot change which leaf predicates are
    evaluated. The rules are bottom-up and idempotent:

    * a structural child with the same operator as its parent is spliced in,
    * ``NOT(NOT x)`` becomes ``x``,
    * an empty AND inside an AND is dropped (true is neutral),
    * an empty OR inside an OR is dropped (false is neutral),
    * a non-root structural node with exactly one child is replaced by it.

    Leaf expressions are never modified, so the set of predicates is preserved.
    Nodes carrying an explicit effect or operand position are kept.
    Labels and per-node ``condition_raw`` text of eliminated nodes are dropped;
    the root keeps its own ``condition_raw``. Use this for a canonical form to
    compare or store, not as a substitute for the lossless tree.
    """
    validate_tree(tree)
    return _canonical(deepcopy(tree), is_root=True)


def _canonical(node, *, is_root):
    node['children'] = [_canonical(child, is_root=False)
                        for child in node.get('children', [])]
    if _has_expression(node) or node['operator_onChildren'] == 'SUBTRACT':
        return node
    kept = []
    for child in node['children']:
        if (_can_remove_group(child) and not child['children'] and
                child['operator_onChildren'] == node['operator_onChildren'] and
                node['operator_onChildren'] in ('AND', 'OR')):
            continue
        kept.append(child)
    spliced = []
    for child in kept:
        # NOT is not associative: NOT(NOT x) is x, not NOT(x's children).
        if (_can_remove_group(child) and child['operator_onChildren'] == node['operator_onChildren'] and
                node['operator_onChildren'] != 'NOT' and child.get('condition_raw') is None):
            spliced.extend(child['children'])
        else:
            spliced.append(child)
    node['children'] = spliced
    if (node['operator_onChildren'] == 'NOT' and len(node['children']) == 1
            and _can_remove_group(node)):
        child = node['children'][0]
        if child['operator_onChildren'] == 'NOT' and _can_remove_group(child):
            node = child['children'][0]
    if (not is_root and _can_remove_group(node) and
            node['operator_onChildren'] != 'NOT' and len(node['children']) == 1):
        node = node['children'][0]
    return node


def strip_database_ids(tree):
    from .postgres.export import strip_database_ids as implementation
    return implementation(tree)


def load_policy_tree(connection, root_id):
    from .postgres.export import load_policy_tree as implementation
    return implementation(connection, root_id)
