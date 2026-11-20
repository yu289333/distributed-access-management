"""Shared policy command-line runner."""
import argparse
import json
import os
from pathlib import Path
from .policyTree import validate_tree
from .policyStore import write_policy_tree


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
