"""Reconstruct an AWS IAM policy document from a policy tree.

This is the outbound half of the AWS morph: it accepts a tree produced by
``awsPolicyEntry.parse_policy`` (or the same tree read back from the database)
and returns an AWS policy dictionary. It is deliberately narrow:

* only AWS trees are accepted; an Azure or GCP tree is not a cross-cloud input,
* statements are emitted as intact JSON expressions, so ``condition_cel`` is
  neither required nor written, and no condition semantics are interpreted,
* API response wrappers are normalised to a top-level policy document.

Because the parser keeps each statement verbatim in ``condition_json``, this
round trip does not depend on a condition translation layer.
"""

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path

if __package__:
    from .awsPolicyEntry import _check_statement
    from .policyTree import validate_tree
else:
    from awsPolicyEntry import _check_statement
    from policyTree import validate_tree


def _check_provider(tree):
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get('provider') != 'AWS':
            raise ValueError('emit_policy requires a tree whose nodes all have provider AWS')
        pending.extend(node.get('children', []))


def _statement_groups(tree):
    """Locate the allow and deny leaves in a parse_policy-shaped tree."""
    children = tree.get('children', [])
    if tree.get('operator') == 'OR':
        return children, []
    if tree.get('operator') == 'AND' and len(children) == 2:
        allowed, excluded = children
        denied = excluded.get('children', [])
        if (allowed.get('operator') == 'OR' and
                excluded.get('operator') == 'NOT' and len(denied) == 1 and
                denied[0].get('operator') == 'OR'):
            return allowed.get('children', []), denied[0].get('children', [])
    raise ValueError('Unexpected AWS tree shape; expected OR(allows) or '
                     'AND(OR(allows), NOT(OR(denies)))')


def _leaf_statement(node, index):
    if node.get('children'):
        raise ValueError(f'Statement {index} must be a leaf')
    statement = node.get('condition_json')
    if not isinstance(statement, dict):
        raise ValueError(f'Statement {index} requires a condition_json object')
    _check_statement(statement, index)
    return deepcopy(statement)


def _statement_container(document):
    """Find the object holding Statement, including API response wrappers."""
    if not isinstance(document, dict):
        return None
    if 'Statement' in document:
        return document
    for key in ('PolicyVersion', 'Document', 'PolicyDocument'):
        value = document.get(key)
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                continue
        found = _statement_container(value)
        if found is not None:
            return found
    return None


def _original_shape(tree):
    """Recover outer metadata and statement order from the root's raw text."""
    raw = tree.get('condition_raw')
    if not raw:
        return {}, []
    try:
        container = _statement_container(json.loads(raw))
    except ValueError:
        return {}, []
    if container is None:
        return {}, []
    metadata = {key: deepcopy(value) for key, value in container.items()
                if key != 'Statement'}
    statements = container['Statement']
    if isinstance(statements, dict):
        statements = [statements]
    return metadata, statements if isinstance(statements, list) else []


def _key(statement):
    return json.dumps(statement, sort_keys=True, separators=(',', ':'))


def _restore_order(original, statements):
    """Reuse the raw order: exact content first, then Sid, then append the rest.

    A statement edited in the tree no longer matches its original JSON, so Sid
    is used to keep it in its original slot. Duplicates are consumed in order.
    """
    if not original:
        return statements
    buckets = {}
    for statement in statements:
        buckets.setdefault(_key(statement), []).append(statement)
    remaining = Counter({key: len(bucket) for key, bucket in buckets.items()})
    slots = [None] * len(original)
    for index, statement in enumerate(original):
        key = _key(statement)
        if remaining[key]:
            slots[index] = buckets[key].pop(0)
            remaining[key] -= 1
    leftovers = [statement for bucket in buckets.values() for statement in bucket]
    for statement in leftovers[:]:
        sid = statement.get('Sid')
        if sid is None:
            continue
        for index, source in enumerate(original):
            if slots[index] is None and isinstance(source, dict) and source.get('Sid') == sid:
                slots[index] = statement
                leftovers.remove(statement)
                break
    return [statement for statement in slots if statement is not None] + leftovers


def emit_policy(tree):
    """Return an AWS policy document reconstructed from an AWS policy tree."""
    validate_tree(tree)
    _check_provider(tree)
    allowed, denied = _statement_groups(tree)
    nodes = list(allowed) + list(denied)
    statements = [_leaf_statement(node, index)
                  for index, node in enumerate(nodes, 1)]
    metadata, original = _original_shape(tree)
    document = metadata
    document['Statement'] = _restore_order(original, statements)
    return document


emit_aws = emit_policy


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Rebuild an AWS policy JSON document from a policy tree')
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


if __name__ == '__main__':
    raise SystemExit(main())
