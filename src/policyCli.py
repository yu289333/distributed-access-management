"""Shared policy command-line runner."""
import argparse
import json
import os
from pathlib import Path
from .conditions.cel import populate_condition_cel
from .policyTree import validate_tree
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
