"""Public entry point for parsing AWS policies."""

from ...cli import run_cli
from ...conditions.cel import populate_condition_cel
from .cel import aws
from .parser import parse_policy as parse_tree


def parse_policy(source, name=None, *, provider_detail='arn:aws', include_cel=True):
    """Parse a AWS policy with optional CEL enrichment."""
    tree = parse_tree(source, name=name, provider_detail=provider_detail)
    return populate_condition_cel(tree, translate=aws) if include_cel else tree


def main(argv=None):
    return run_cli(parse_tree, argv, translate=aws)


if __name__ == '__main__':
    raise SystemExit(main())
