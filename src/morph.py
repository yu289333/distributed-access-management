"""Provider-neutral policy morph: decode a source, encode a target.

The point of this module is the shape of the dependency graph. A source adapter
reads its policy and returns neutral statements (``policyStatement``); the
engine decodes their actions into neutral atoms and the target adapter encodes
them. Adding a cloud means registering one adapter pair (reader + decoder for a
source, encoder + builder for a target); it does not add a translator for every
existing provider. Cross-cloud translation is ``read(A) -> atoms -> encode(B)``.

Today only ``aws`` is a source and only ``azure`` is a target, but
``register_source()`` and ``register_target()`` are the extension points.
"""

import json

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import awsVocabulary, azureVocabulary
from src.policyTree import validate_tree

SOURCES = {'aws': awsVocabulary.read}
DECODERS = {'aws': awsVocabulary.decode}
TARGETS = {'azure': (azureVocabulary.encode, azureVocabulary.build)}


def register_source(name, reader, decoder):
    """Register a source adapter pair: tree -> neutral statements, action -> atom."""
    if not isinstance(name, str) or not name:
        raise ValueError('Source name must be nonempty text')
    if name in SOURCES or name in DECODERS:
        raise ValueError(f'Source already registered: {name}')
    if not callable(reader) or not callable(decoder):
        raise ValueError('Source reader and decoder must be callable')
    SOURCES[name] = reader
    DECODERS[name] = decoder


def register_target(name, encoder, builder):
    """Register a target adapter pair: atoms -> action string, and document build."""
    if not isinstance(name, str) or not name:
        raise ValueError('Target name must be nonempty text')
    if name in TARGETS:
        raise ValueError(f'Target already registered: {name}')
    if not callable(encoder) or not callable(builder):
        raise ValueError('Target encoder and builder must be callable')
    TARGETS[name] = (encoder, builder)


def _dedupe(values):
    seen, result = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def translate(tree, *, source='aws', target='azure', name=None):
    """Return ``(target_document, report)`` for a source policy tree."""
    if source not in SOURCES or source not in DECODERS:
        raise ValueError(f'Unsupported source: {source}')
    if target not in TARGETS:
        raise ValueError(f'Unsupported target: {target}')

    statements = SOURCES[source](tree)
    decode = DECODERS[source]
    encode, build = TARGETS[target]

    actions, not_actions = [], []
    report = {'mapped': {}, 'unmapped': [], 'warnings': [], 'resources': []}
    for statement in statements:
        effect = statement['effect']
        for action in statement['actions']:
            neutral = decode(action)
            if neutral is None:
                report['unmapped'].append(action)
                continue
            encoded = encode(neutral)
            report['mapped'][action] = encoded
            (actions if effect == 'allow' else not_actions).append(encoded)
        for field, value in statement['untranslated']:
            report['unmapped'].append(value)
            report['warnings'].append(f'{field} is not translated')
        for resource in statement['resources']:
            if resource not in report['resources']:
                report['resources'].append(resource)
        for operator in statement['conditions']:
            report['warnings'].append(f'condition {operator} is not translated')

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
    from src.azurePolicyEntry import parse_policy
    result = parse_policy(json.dumps(document))
    validate_tree(result)
    return result, report
