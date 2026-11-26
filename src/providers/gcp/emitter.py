"""Reconstruct a GCP IAM policy from a policy tree.

This is the outbound half of the GCP morph. It accepts a tree produced by
``gcpPolicyEntry.parse_policy`` (or the same tree read back from the database)
and returns the GCP IAM policy document. It is deliberately narrow:

* only GCP trees are accepted; an AWS or Azure tree is not a cross-cloud input,
* bindings and Unified Access Policy rules are rebuilt from condition leaves,
* outer metadata (version, etag) is recovered from the root's ``condition_raw``.
"""

import argparse
import json
from copy import deepcopy
from pathlib import Path

from ...policyTree import validate_tree
from .parser import _check_access_rule, _has_access_rules


def _check_provider(tree):
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get('provider') != 'GCP':
            raise ValueError('emit_policy requires a tree whose nodes all have provider GCP')
        pending.extend(node.get('children', []))


def _raw(tree):
    raw = tree.get('condition_raw')
    if not raw:
        return {}
    try:
        document = json.loads(raw)
    except ValueError:
        return {}
    return document if isinstance(document, dict) else {}


def _binding(node):
    role = None
    members = []
    condition = None
    for child in node.get('children', []):
        expression = child.get('condition_json')
        name = child.get('name')
        if name == 'Role' and isinstance(expression, dict) and 'role' in expression:
            role = expression['role']
        elif name == 'Members':
            members = [deepcopy(member['condition_json']['member'])
                       for member in child.get('children', [])]
        elif name == 'IAM condition' and isinstance(expression, dict) and 'condition' in expression:
            condition = deepcopy(expression['condition'])
        else:
            raise ValueError(f'Unexpected GCP binding node: {name!r}')
    if not isinstance(role, str) or not role:
        raise ValueError('GCP binding requires a role')
    if not members:
        raise ValueError('GCP binding requires at least one member')
    binding = {'role': role, 'members': members}
    if condition is not None:
        binding['condition'] = condition
    return binding


def _access_rules(tree):
    children = tree['children']
    if len(children) != 2:
        raise ValueError('GCP Unified Access Policy requires two root groups')
    allowed, excluded = children
    if allowed['operator_onChildren'] == 'NOT':
        allowed, excluded = excluded, allowed
    if excluded['operator_onChildren'] != 'NOT':
        raise ValueError('GCP Unified Access Policy requires a NOT group for DENY rules')
    denied, = excluded['children']
    rules = {}
    for operand, effect in ((allowed, 'ALLOW'), (denied, 'DENY')):
        groups = operand['children'] if operand['operator_onChildren'] == 'OR' else [operand]
        for group in groups:
            position = group.get('child_position')
            if position is None or position in rules:
                raise ValueError('GCP Unified Access Policy rules require distinct source positions')
            rule = {}
            for leaf in group.get('children', []):
                expression = leaf.get('condition_json')
                if not isinstance(expression, dict) or len(expression) != 1:
                    raise ValueError('Expected a single-field GCP Unified Access Policy rule leaf')
                if rule.keys() & expression.keys():
                    raise ValueError('Duplicate GCP Unified Access Policy rule field')
                rule.update(deepcopy(expression))
            _check_access_rule(rule, position + 1)
            if rule['effect'] != effect:
                raise ValueError('GCP Unified Access Policy rule effect disagrees with its operand')
            rules[position] = rule
    if not rules:
        raise ValueError('GCP Unified Access Policy requires at least one rule')
    return [rules[position] for position in sorted(rules)]


def _emit_access_policy(tree, document):
    target = document
    if not _has_access_rules(document):
        for wrapper in ('policy', 'Policy'):
            candidate = document.get(wrapper)
            if isinstance(candidate, dict) and _has_access_rules(candidate):
                target = candidate
                break
    details = target.get('details')
    if not isinstance(details, dict):
        details = {}
        target['details'] = details
    details['rules'] = _access_rules(tree)
    return document


def emit_policy(tree):
    """Return the GCP IAM policy reconstructed from a GCP policy tree."""
    validate_tree(tree)
    _check_provider(tree)
    document = _raw(tree)
    if tree['operator_onChildren'] == 'AND':
        return _emit_access_policy(tree, document)
    document['bindings'] = [_binding(node) for node in tree.get('children', [])]
    return document


emit_gcp = emit_policy


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Rebuild a GCP IAM policy from a policy tree')
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
