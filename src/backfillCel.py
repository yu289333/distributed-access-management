"""Preview or atomically fill missing CEL on existing leaf rows.

python -m src.backfillCel          # preview; no writes
python -m src.backfillCel --apply  # write only missing leaf CEL
"""
import argparse
import os

from .conditionCel import populate_condition_cel
from .policyTree import make_node


def backfill(connection, apply=False):
    updates = []
    with connection:
        with connection.cursor() as cursor:
            # A stable table prevents concurrent imports from changing leaf status.
            if apply:
                cursor.execute('LOCK TABLE policy IN SHARE ROW EXCLUSIVE MODE')
            cursor.execute('''SELECT id, name, provider, provider_detail, operator,
                                     condition_json, condition_raw
                              FROM policy p WHERE condition_cel IS NULL
                              AND NOT EXISTS (SELECT 1 FROM policy c WHERE c.parent=p.id)
                              ORDER BY id''')
            for row_id, name, provider, detail, operator, expression, raw in cursor.fetchall():
                node = make_node(name, provider, detail, operator,
                                 condition_json=expression, condition_raw=raw)
                populate_condition_cel(node)
                if node['condition_cel'] is None:
                    raise ValueError(f'Row {row_id}: {node["comment"]}; no updates committed')
                updates.append((node['condition_cel'], row_id))
            if apply:
                cursor.executemany('UPDATE policy SET condition_cel=%s WHERE id=%s', updates)
    return updates


def main():
    import psycopg2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    connection = psycopg2.connect(os.environ.get('DATABASE_URL', ''))
    try:
        updates = backfill(connection, apply=args.apply)
    finally:
        connection.close()
    for expression, row_id in updates:
        print(f'{row_id}: {expression}')
    print(f'{"Updated" if args.apply else "Would update"} {len(updates)} leaf rows')


if __name__ == '__main__':
    main()
