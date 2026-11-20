"""Convert stored raw/JSON leaf conditions to expressions atomically.

python -m src.convertConditions          # preview; no writes
python -m src.convertConditions --apply  # write only missing leaf CEL
"""
import argparse
import os

from .conditionExpression import populate_condition_cel
from .policyTree import make_node


def convert_conditions(connection, apply=False, replace=False):
    updates = []
    normalized_updates = []
    with connection:
        with connection.cursor() as cursor:
            # A stable table prevents concurrent imports from changing leaf status.
            if apply:
                cursor.execute('LOCK TABLE policy IN SHARE ROW EXCLUSIVE MODE')
            filter_clause = '' if replace else 'condition_cel IS NULL AND '
            cursor.execute('''SELECT id, name, provider, provider_detail, operator,
                                     condition_json, condition_raw, condition_origin
                              FROM policy p WHERE ''' + filter_clause + '''NOT EXISTS (SELECT 1 FROM policy c WHERE c.parent=p.id)
                              ORDER BY id''')
            for row_id, name, provider, detail, operator, expression, raw, origin in cursor.fetchall():
                node = make_node(name, provider, detail, operator,
                                 condition_json=expression, condition_raw=raw, condition_origin=origin)
                populate_condition_cel(node)
                if node['condition_cel'] is None:
                    raise ValueError(f'Row {row_id}: {node["comment"]}; no updates committed')
                from psycopg2.extras import Json
                updates.append((node['condition_cel'], row_id))
                normalized_updates.append((node['condition_cel'],
                    Json(node['condition_json']) if node['condition_json'] is not None else None,
                    node['condition_origin'], row_id))
            if apply:
                cursor.executemany('UPDATE policy SET condition_cel=%s, condition_json=%s, condition_origin=%s WHERE id=%s', normalized_updates)
    return updates


def main():
    import psycopg2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--replace', action='store_true', help='Reconvert existing expressions too')
    args = parser.parse_args()
    connection = psycopg2.connect(os.environ.get('DATABASE_URL', ''))
    try:
        updates = convert_conditions(connection, apply=args.apply, replace=args.replace)
    finally:
        connection.close()
    for expression, row_id in updates:
        print(f'{row_id}: {expression}')
    print(f'{"Updated" if args.apply else "Would update"} {len(updates)} leaf rows')


if __name__ == '__main__':
    main()
