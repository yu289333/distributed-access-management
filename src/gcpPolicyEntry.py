"""Public entry point for parsing GCP policies."""

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.policyCli import run_cli
from src.providers.gcp.parser import parse_policy


def main(argv=None):
    return run_cli(parse_policy, argv)


if __name__ == '__main__':
    raise SystemExit(main())
