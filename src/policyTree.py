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
