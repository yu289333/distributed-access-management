"""Backward-compatible AWS → Azure entry point.

The implementation is provider-neutral now: ``morph.translate`` decodes a source
tree into neutral atoms and encodes them with the target adapter. This module
keeps the original function names and the command line interface.
"""

import argparse
import json
import sys
from pathlib import Path

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awsPolicyEntry import parse_policy as parse_aws
from src.awsVocabulary import decode
from src.azureVocabulary import encode
from src.morph import translate, translate_tree


def map_action(action):
    """Compatibility helper: one AWS action to one Azure action pattern."""
    neutral = decode(action)
    return None if neutral is None else encode(neutral)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Translate an AWS IAM policy into an Azure RBAC role definition')
    parser.add_argument('file', type=Path, help='One AWS policy JSON document')
    parser.add_argument('--name', help='Override the Azure role name')
    parser.add_argument('--report', action='store_true',
                        help='Print the mapping report to stderr')
    args = parser.parse_args(argv)
    try:
        source = args.file.read_text(encoding='utf-8-sig')
        document, report = translate(parse_aws(source),
                                     name=args.name or args.file.stem)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(document, indent=2))
    if args.report:
        sys.stderr.write(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
