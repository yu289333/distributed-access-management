"""Public entry point for parsing Azure policies."""

from ...cli import run_cli
from ...conditions.cel import populate_condition_cel
from .cel import azure
from .parser import parse_policy as parse_tree


def parse_policy(source, name=None, *, include_cel=True):
    """Parse a Azure policy with optional CEL enrichment."""
    tree = parse_tree(source, name=name)
    return populate_condition_cel(tree, translate=azure) if include_cel else tree


def main(argv=None):
    return run_cli(parse_tree, argv, translate=azure)


if __name__ == '__main__':
    raise SystemExit(main())
