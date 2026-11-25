"""PostgreSQL policy tree persistence."""
from ..policyTree import COLUMNS, validate_tree
import json


def insert_policy_tree(cursor, tree, *, table='policy', schema=None, parent_id=None):
    """Insert without committing. The caller owns the transaction; return root ID."""
    validate_tree(tree)
    from psycopg2 import sql
    from psycopg2.extras import Json

    identifier = sql.Identifier(schema, table) if schema else sql.Identifier(table)
    query = sql.SQL('''
        INSERT INTO {} (parent, name, display_name, comment, provider,
            provider_detail, "operator_onChildren", condition_raw, condition_cel,
            condition_json, condition_raw_type, effect)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s) RETURNING id
    ''').format(identifier)

    def insert(node, parent):
        values = [node.get(key) for key in COLUMNS]
        if values[COLUMNS.index('condition_json')] is not None:
            values[COLUMNS.index('condition_json')] = Json(values[COLUMNS.index('condition_json')], dumps=lambda value: json.dumps(value, allow_nan=False))
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
