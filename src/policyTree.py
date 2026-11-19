"""Common policy-tree format, validation, and PostgreSQL persistence.

Each node is a dictionary of policy-table columns plus a children list. Database
IDs and parent IDs are assigned on insertion. OR with no children is empty/false;
AND with no children is universal/true. NOT always has exactly one child.
"""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path


COLUMNS = ('name', 'display_name', 'comment', 'provider', 'provider_detail',
           'operator', 'condition_raw', 'condition_cel', 'condition_json')
OPERATORS = {'AND', 'OR', 'XOR', 'NOT'}


def load_document(source):
    """Return an independent JSON object; reject duplicates and non-JSON values."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'Duplicate JSON key: {key}')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f'Invalid JSON constant: {value}')

    if isinstance(source, str):
        document = json.loads(source, object_pairs_hook=unique,
                              parse_constant=invalid_constant)
    else:
        document = deepcopy(source)
    if not isinstance(document, dict):
        raise ValueError('A policy document must be a JSON object')
    json.dumps(document, allow_nan=False)
    return document


def make_node(name, provider, provider_detail, operator='AND', *, children=None,
              condition_json=None, condition_raw=None, condition_cel=None,
              display_name=None, comment=None):
    """Construct a node using only column names from db/policy.sql."""
    return dict(name=name, display_name=display_name, comment=comment,
                provider=provider, provider_detail=provider_detail,
                operator=operator, condition_raw=condition_raw,
                condition_cel=condition_cel, condition_json=condition_json,
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
        for child in children:
            visit(child)

    visit(tree)


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
                node['operator'] != 'NOT'):
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


def insert_policy_tree(cursor, tree, *, table='policy', schema=None, parent_id=None):
    """Insert without committing. The caller owns the transaction; return root ID."""
    validate_tree(tree)
    from psycopg2 import sql
    from psycopg2.extras import Json

    identifier = sql.Identifier(schema, table) if schema else sql.Identifier(table)
    query = sql.SQL('''
        INSERT INTO {} (parent, name, display_name, comment, provider,
            provider_detail, operator, condition_raw, condition_cel, condition_json)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb) RETURNING id
    ''').format(identifier)

    def insert(node, parent):
        values = [node.get(key) for key in COLUMNS]
        if values[-1] is not None:
            values[-1] = Json(values[-1], dumps=lambda value: json.dumps(value, allow_nan=False))
        cursor.execute(query, (parent, *values))
        node_id = cursor.fetchone()[0]
        for child in node.get('children', []):
            insert(child, node_id)
        return node_id

    return insert(tree, parent_id)


def load_policy_tree(cursor, root_id, *, table='policy', schema=None):
    """Read one policy tree back from the database; return a fresh tree dict.

    Rows are fetched with one recursive query and reassembled by ``parent``.
    The result is validated, so a truncated or cyclic subtree raises instead of
    returning a partial tree. The caller owns the transaction and the cursor.
    """
    from psycopg2 import sql

    identifier = sql.Identifier(schema, table) if schema else sql.Identifier(table)
    columns = sql.SQL(', ').join(sql.Identifier(column) for column in COLUMNS)
    query = sql.SQL('''
        WITH RECURSIVE subtree AS (
            SELECT id, parent, {columns} FROM {table} WHERE id = %s
            UNION ALL
            SELECT child.id, child.parent, {columns} FROM {table} AS child
            JOIN subtree AS parent ON child.parent = parent.id
        )
        SELECT id, parent, {columns} FROM subtree ORDER BY id
    ''').format(columns=columns, table=identifier)
    cursor.execute(query, (root_id,))
    rows = cursor.fetchall()

    nodes, children = {}, {}
    for row in rows:
        node_id, parent_id = row[0], row[1]
        node = dict(zip(COLUMNS, row[2:]))
        node['children'] = []
        nodes[node_id] = node
        children.setdefault(parent_id, []).append(node_id)
    if root_id not in nodes:
        raise ValueError(f'No policy row with id {root_id}')

    def build(node_id, seen):
        if node_id in seen:
            raise ValueError('Policy rows contain a parent cycle')
        seen.add(node_id)
        node = nodes[node_id]
        node['children'] = [build(child, seen)
                            for child in children.get(node_id, [])]
        return node

    tree = build(root_id, set())
    validate_tree(tree)
    return tree


def write_policy_tree(connection, tree, *, table='policy', schema=None):
    """Commit one whole tree, or roll it back on failure; return its root ID.

    Use a dedicated connection: its current transaction is committed/rolled back.
    This function leaves closing the connection to its caller.
    """
    validate_tree(tree)
    if connection.autocommit:
        raise ValueError('Policy imports require autocommit to be disabled')
    with connection:
        with connection.cursor() as cursor:
            return insert_policy_tree(cursor, tree, table=table, schema=schema)


def run_cli(parse_policy, argv=None):
    """Shared command-line runner used by both provider entry modules."""
    parser = argparse.ArgumentParser(description=parse_policy.__doc__)
    parser.add_argument('file', type=Path, help='One JSON policy document')
    parser.add_argument('--name', help='Override the policy name')
    parser.add_argument('--dry-run', action='store_true', help='Print the tree without a database')
    args = parser.parse_args(argv)
    try:
        tree = parse_policy(args.file.read_text(encoding='utf-8-sig'), name=args.name)
        validate_tree(tree)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    if args.dry_run:
        print(json.dumps(tree, indent=2))
        return 0
    import psycopg2
    connection = psycopg2.connect(os.environ.get('DATABASE_URL', ''))
    try:
        root_id = write_policy_tree(connection, tree)
    finally:
        connection.close()
    print(f'Stored {tree["name"]!r} with root ID {root_id}')
    return 0
