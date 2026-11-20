"""Common policy-tree format, validation, and PostgreSQL persistence.

Each node is a dictionary of policy-table columns plus a children list. Database
IDs and parent IDs are assigned on insertion. OR with no children is empty/false;
AND with no children is universal/true. NOT always has exactly one child.
"""

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
