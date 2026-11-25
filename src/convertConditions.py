"""Convert stored raw/JSON leaf conditions to expressions atomically.

python -m src.convertConditions          # preview; no writes
python -m src.convertConditions --apply  # write only missing leaf CEL
"""
import argparse
import os

from .conditionExpression import populate_condition_cel
from .postgres.backfill import convert_conditions as backfill


def convert_conditions(connection, apply=False, replace=False):
    return backfill(connection, populate=populate_condition_cel, apply=apply, replace=replace)


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
