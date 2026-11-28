"""Shared policy command-line runners and the backfill command."""
import argparse
import json
import os
from pathlib import Path
from .conditions.cel import populate_condition_cel
from .tree import validate_tree
from .conditions.expression import populate_condition_cel as populate_by_provider
from .postgres.backfill import convert_conditions as backfill
from .postgres.store import write_policy_tree


def run_cli(parse_policy, argv=None, *, translate=None):
    """Read, enrich, and optionally store a parsed policy."""
    parser = argparse.ArgumentParser(description=parse_policy.__doc__)
    parser.add_argument('file', type=Path, help='One JSON policy document')
    parser.add_argument('--name', help='Override the policy name')
    parser.add_argument('--dry-run', action='store_true', help='Print the tree without a database')
    parser.add_argument('--no-cel', action='store_true', help='Skip CEL enrichment')
    args = parser.parse_args(argv)
    try:
        tree = parse_policy(args.file.read_text(encoding='utf-8-sig'), name=args.name)
        if translate is not None and not args.no_cel:
            populate_condition_cel(tree, translate=translate)
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


def run_emit_cli(description, emit_policy, argv=None):
    """Read a tree JSON file, emit a document, and print it."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('file', type=Path,
                        help='A policy tree JSON file, e.g. --dry-run output')
    parser.add_argument('--indent', type=int, default=2,
                        help='Indentation of the printed JSON (default: 2)')
    args = parser.parse_args(argv)
    try:
        tree = json.loads(args.file.read_text(encoding='utf-8-sig'))
        document = emit_policy(tree)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(document, indent=args.indent))
    return 0


def convert_conditions(connection, apply=False, replace=False):
    return backfill(connection, populate=populate_by_provider,
                    apply=apply, replace=replace)


def main():
    """Preview or apply missing CEL expressions on stored leaf rows."""
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
