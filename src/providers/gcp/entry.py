"""Public entry point for parsing GCP policies."""

from ...cli import run_cli
from .parser import parse_policy


def main(argv=None):
    return run_cli(parse_policy, argv)


if __name__ == '__main__':
    raise SystemExit(main())
