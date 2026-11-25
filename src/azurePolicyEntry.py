"""Public entry point for parsing Azure policies."""

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.policyCli import run_cli
from src.conditions.cel import populate_condition_cel
from src.providers.azure.cel import azure
from src.providers.azure.parser import parse_policy as parse_tree


def parse_policy(source, name=None, *, include_cel=True):
    """Parse a Azure policy with optional CEL enrichment."""
    tree = parse_tree(source, name=name)
    return populate_condition_cel(tree, translate=azure) if include_cel else tree


def main(argv=None):
    return run_cli(parse_tree, argv, translate=azure)


if __name__ == '__main__':
    raise SystemExit(main())
