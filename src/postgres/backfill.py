"""Convert stored leaf conditions in one PostgreSQL transaction."""
from ..tree import make_node


def convert_conditions(connection, *, populate, apply=False, replace=False):
    updates = []
    normalized_updates = []
    with connection:
        with connection.cursor() as cursor:
            # A stable table prevents concurrent imports from changing leaf status.
            if apply:
                cursor.execute('LOCK TABLE policy IN SHARE ROW EXCLUSIVE MODE')
            filter_clause = '' if replace else 'condition_cel IS NULL AND '
            cursor.execute('''SELECT id, name, provider, provider_detail, "operator_onChildren",
                                     condition_json, condition_raw, condition_raw_type
                              FROM policy p WHERE ''' + filter_clause + '''NOT EXISTS (SELECT 1 FROM policy c WHERE c.parent=p.id)
                              ORDER BY id''')
            for row_id, name, provider, detail, operator, expression, raw, origin in cursor.fetchall():
                node = make_node(name, provider, detail, operator,
                                 condition_json=expression, condition_raw=raw, condition_raw_type=origin)
                populate(node)
                if node['condition_cel'] is None:
                    raise ValueError(f'Row {row_id}: {node["comment"]}; no updates committed')
                from psycopg2.extras import Json
                updates.append((node['condition_cel'], row_id))
                normalized_updates.append((node['condition_cel'],
                    Json(node['condition_json']) if node['condition_json'] is not None else None,
                    node['condition_raw_type'], row_id))
            if apply:
                cursor.executemany('UPDATE policy SET condition_cel=%s, condition_json=%s, condition_raw_type=%s WHERE id=%s', normalized_updates)
    return updates
