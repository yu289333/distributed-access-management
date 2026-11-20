"""Provider-neutral policy morph: decode a source, encode a target.

The point of this module is the shape of the dependency graph. Adding a cloud
means registering one adapter pair (read/decode for a source, encode/build for a
target); it does not add a translator for every existing provider. Cross-cloud
translation is then ``decode(A) -> atoms -> encode(B)``.

Today only ``aws`` is a source and only ``azure`` is a target, but
``register_target()`` and the ``SOURCES`` map are the extension points.
"""

import json

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import awsVocabulary, azureVocabulary
from src.policyTree import validate_tree

UNTRANSLATED_FIELDS = ('NotAction', 'NotResource', 'Principal', 'NotPrincipal')

SOURCES = {'aws': awsVocabulary.read}
DECODERS = {'aws': awsVocabulary.decode}
TARGETS = {'azure': (azureVocabulary.encode, azureVocabulary.build)}


def register_target(name, encoder, builder):
    """Register a target adapter pair: atoms -> action string, and document build."""
    if not isinstance(name, str) or not name:
        raise ValueError('Target name must be nonempty text')
    if name in TARGETS:
        raise ValueError(f'Target already registered: {name}')
    if not callable(encoder) or not callable(builder):
        raise ValueError('Target encoder and builder must be callable')
    TARGETS[name] = (encoder, builder)


def _values(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _dedupe(values):
    seen, result = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def translate(tree, *, source='aws', target='azure', name=None):
    """Return ``(target_document, report)`` for a source policy tree."""
    if source not in SOURCES:
        raise ValueError(f'Unsupported source: {source}')
    if target not in TARGETS:
        raise ValueError(f'Unsupported target: {target}')

    statements = SOURCES[source](tree)
    decode = DECODERS[source]
    encode, build = TARGETS[target]

    actions, not_actions = [], []
    report = {'mapped': {}, 'unmapped': [], 'warnings': [], 'resources': []}
    for statement in statements:
        effect = statement['Effect']
        for action in _values(statement.get('Action')):
            neutral = decode(action)
            if neutral is None:
                report['unmapped'].append(action)
                continue
            encoded = encode(neutral)
            report['mapped'][action] = encoded
            (actions if effect == 'Allow' else not_actions).append(encoded)
        for field in UNTRANSLATED_FIELDS:
            if field in statement:
                report['unmapped'].extend(_values(statement[field]))
                report['warnings'].append(f'{field} is not translated')
        for resource in _values(statement.get('Resource')):
            if resource not in report['resources']:
                report['resources'].append(resource)
        for operator in sorted(statement.get('Condition', {})):
            report['warnings'].append(f'AWS condition {operator} is not translated')

    if not_actions:
        report['warnings'].append(
            'Azure notActions is scoped to one permissions block and does not '
            'override grants from other roles; AWS Deny is a global exclusion')
    non_wildcard = [resource for resource in report['resources'] if resource != '*']
    if non_wildcard:
        report['warnings'].append(
            'Resource ARNs are not translated to assignable scopes: '
            + ', '.join(non_wildcard))

    candidate = tree.get('name')
    role_name = name or (candidate if candidate and candidate != 'Statement'
                         else 'Translated AWS policy')
    return build(role_name, _dedupe(actions), _dedupe(not_actions)), report


def translate_tree(tree, *, source='aws', target='azure', name=None):
    """Return the target policy tree and report for a translated tree."""
    if target != 'azure':
        raise ValueError('translate_tree only rebuilds Azure trees')
    document, report = translate(tree, source=source, target=target, name=name)
    from .azurePolicyEntry import parse_policy
    result = parse_policy(json.dumps(document))
    validate_tree(result)
    return result, report
