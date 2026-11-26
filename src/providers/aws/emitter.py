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

from .parser import _check_statement
from ...policyTree import validate_tree


def _check_provider(tree):
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get('provider') != 'AWS':
            raise ValueError('emit_policy requires a tree whose nodes all have provider AWS')
        pending.extend(node.get('children', []))


def _group(node, label):
    """A group is an OR of statement groups, a group, or a leaf."""
    if node.get('operator_onChildren') == 'OR':
        return node.get('children', [])
    if node.get('children') or node.get('condition_json') is not None:
        return [node]
    raise ValueError(f'Unexpected AWS tree shape: {label} must be OR(statements) or a statement')


def _statement_groups(tree):
    """Locate the allow and deny statement groups in a parse_policy-shaped tree."""
    children = tree.get('children', [])
    if tree.get('operator_onChildren') == 'OR':
        return children, []
    if tree.get('operator_onChildren') == 'AND' and len(children) == 2:
        allowed, excluded = children
        if allowed.get('operator_onChildren') == 'NOT':
            allowed, excluded = excluded, allowed
        denied = excluded.get('children', [])
        if excluded.get('operator_onChildren') == 'NOT' and len(denied) == 1:
            return _group(allowed, 'allows'), _group(denied[0], 'denies')
    raise ValueError('Unexpected AWS tree shape; expected OR(statements) or '
                     'AND(OR(allows), NOT(OR(denies)))')


def _sid(node):
    """Recover Sid, which the parser keeps as the group's label, not a leaf."""
    display = node.get('display_name') or ''
    prefix = '"Sid": '
    return json.loads(display[len(prefix):]) if display.startswith(prefix) else None


def _statement(node, index):
    """Rebuild one statement from a group of single-field leaves.

    The parser stores one leaf per statement field (``{'Action': [...]}``,
    ``{'Resource': ...}``, ...). Older trees may hold the whole statement in a
    single leaf, which is also accepted.
    """
    if node.get('children'):
        statement = {}
        for child in node['children']:
            expression = child.get('condition_json')
            if child.get('children') or not isinstance(expression, dict) or len(expression) != 1:
                raise ValueError(f'Statement {index} fields must be single-key leaves')
            statement.update(deepcopy(expression))
    else:
        statement = node.get('condition_json')
        if not isinstance(statement, dict):
            raise ValueError(f'Statement {index} requires a condition_json object')
        statement = deepcopy(statement)
    sid = _sid(node)
    if sid is not None:
        statement['Sid'] = sid
    _check_statement(statement, index)
    return statement



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
        return {}, [], False
    try:
        container = _statement_container(json.loads(raw))
    except ValueError:
        return {}, [], False
    if container is None:
        return {}, [], False
    metadata = {key: deepcopy(value) for key, value in container.items()
                if key != 'Statement'}
    statements = container['Statement']
    single = isinstance(statements, dict)
    if single:
        statements = [statements]
    return metadata, statements if isinstance(statements, list) else [], single


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
    statements = [_statement(node, index)
                  for index, node in enumerate(nodes, 1)]
    metadata, original, single = _original_shape(tree)
    document = metadata
    ordered = _restore_order(original, statements)
    document['Statement'] = ordered[0] if single and len(ordered) == 1 else ordered
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
