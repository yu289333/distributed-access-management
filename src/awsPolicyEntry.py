"""Public entry point for parsing AWS policies."""

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.policyCli import run_cli
from src.conditions.cel import populate_condition_cel
from src.providers.aws.cel import aws
from src.providers.aws.parser import parse_policy as parse_tree


def parse_policy(source, name=None, *, provider_detail='arn:aws', include_cel=True):
    """Parse a AWS policy with optional CEL enrichment."""
    tree = parse_tree(source, name=name, provider_detail=provider_detail)
    return populate_condition_cel(tree, translate=aws) if include_cel else tree


def main(argv=None):
    return run_cli(parse_tree, argv, translate=aws)


if __name__ == '__main__':
    raise SystemExit(main())
