"""Common policy-tree format, validation, and tree utilities.

Each node is a dictionary of policy-table columns plus a children list. Database
IDs and parent IDs are assigned on insertion. OR with no children is empty/false;
AND with no children is universal/true. NOT always has exactly one child.

Persistence lives in ``policyStore``, export in ``policyExport``, and the CLI in
``policyCli``; the wrappers below keep the historical imports working.
"""

from copy import deepcopy
import json


COLUMNS = ('name', 'display_name', 'comment', 'provider', 'provider_detail',
           'operator', 'condition_raw', 'condition_cel', 'condition_json', 'condition_origin')
OPERATORS = {'AND', 'OR', 'XOR', 'NOT'}


def make_node(name, provider, provider_detail, operator='AND', *, children=None,
              condition_json=None, condition_raw=None, condition_cel=None,
              display_name=None, comment=None, condition_origin=None):
    """Construct a node using only column names from db/policy.sql."""
    return dict(name=name, display_name=display_name, comment=comment,
                provider=provider, provider_detail=provider_detail,
                operator=operator, condition_raw=condition_raw,
                condition_cel=condition_cel, condition_json=condition_json,
                condition_origin=condition_origin or ('json' if condition_json is not None else None),
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
        if node.get('operator') not in OPERATORS:
            raise ValueError('Policy operator must be AND, OR, XOR, or NOT')
        for key in COLUMNS:
            if key != 'condition_json' and node.get(key) is not None:
                if not isinstance(node[key], str):
                    raise ValueError(f'{key} must be text or None')
        children = node.get('children', [])
        if not isinstance(children, list):
            raise ValueError('children must be a list')
        if node['operator'] == 'NOT' and len(children) != 1:
            raise ValueError('NOT requires exactly one child')
        if children and any(node.get(key) is not None for key in
                            ('condition_json', 'condition_cel')):
            raise ValueError('Expression nodes must be leaves; use a parent to combine them')
        try:
            json.dumps(node.get('condition_json'), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError('condition_json must be JSON serializable') from exc
        if node.get('condition_json') is not None and node.get('condition_raw') is not None:
            from .conditionSource import normalize_condition
            normalize_condition(node['condition_json'], node['condition_raw'], node.get('condition_origin'))
        for child in children:
            visit(child)

    visit(tree)


# Compatibility imports: retain existing public APIs while implementations live
# in focused modules. Lazy wrappers avoid circular dependencies.
from .policyDocument import load_document


def insert_policy_tree(*args, **kwargs):
    from .policyStore import insert_policy_tree as implementation
    return implementation(*args, **kwargs)


def write_policy_tree(*args, **kwargs):
    from .policyStore import write_policy_tree as implementation
    return implementation(*args, **kwargs)


def run_cli(*args, **kwargs):
    from .policyCli import run_cli as implementation
    return implementation(*args, **kwargs)


def _has_expression(node):
    return node.get('condition_json') is not None or node.get('condition_cel') is not None


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
    Labels and per-node ``condition_raw`` text of eliminated nodes are dropped;
    the root keeps its own ``condition_raw``. Use this for a canonical form to
    compare or store, not as a substitute for the lossless tree.
    """
    validate_tree(tree)
    return _canonical(deepcopy(tree), is_root=True)


def _canonical(node, *, is_root):
    node['children'] = [_canonical(child, is_root=False)
                        for child in node.get('children', [])]
    if _has_expression(node):
        return node
    kept = []
    for child in node['children']:
        if (not _has_expression(child) and not child['children'] and
                child['operator'] == node['operator'] and
                node['operator'] in ('AND', 'OR')):
            continue
        kept.append(child)
    spliced = []
    for child in kept:
        # NOT is not associative: NOT(NOT x) is x, not NOT(x's children).
        if (not _has_expression(child) and child['operator'] == node['operator'] and
                node['operator'] != 'NOT' and child.get('condition_raw') is None):
            spliced.extend(child['children'])
        else:
            spliced.append(child)
    node['children'] = spliced
    if node['operator'] == 'NOT' and len(node['children']) == 1:
        child = node['children'][0]
        if not _has_expression(child) and child['operator'] == 'NOT':
            node = child['children'][0]
    if (not is_root and not _has_expression(node) and
            node['operator'] != 'NOT' and len(node['children']) == 1):
        node = node['children'][0]
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


def load_policy_tree(connection, root_id):
    """Read one policy tree back as a validated tree without database ids."""
    from .policyExport import export_policy_tree

    tree = strip_database_ids(export_policy_tree(connection, root_id))
    validate_tree(tree)
    return tree
