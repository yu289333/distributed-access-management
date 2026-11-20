"""Best-effort translation of an AWS IAM policy into an Azure RBAC role.

This is the first cross-cloud step: the AWS tree is read back into a policy
document, each statement's actions are mapped onto Azure resource-provider
actions, and the result is emitted as a custom RBAC role definition. The Azure
document is then parsed back into the same neutral tree, so the translation
still flows through the shared format.

The mapping is intentionally conservative and explainable, not a proof of
equivalence:

* ``service:Verb*`` maps to ``<namespace>/*/read`` or ``<namespace>/*/write``
  from a small service table and a verb heuristic,
* ``Allow`` actions become ``actions``; ``Deny`` actions become ``notActions``,
  which in Azure are block-scoped and can be re-granted by another role,
* ``Resource`` ARNs, ``Condition`` blocks, ``NotAction``/``NotResource`` and
  ``Principal`` are not translated; they are reported instead.

Anything the mapping cannot express is returned in the report rather than
silently dropped.
"""

import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .awsPolicyEmitter import emit_policy as emit_aws
    from .awsPolicyEntry import parse_policy as parse_aws
    from .azurePolicyEntry import parse_policy as parse_azure
    from .policyTree import validate_tree
else:  # pragma: no cover - direct script use
    from awsPolicyEmitter import emit_policy as emit_aws
    from awsPolicyEntry import parse_policy as parse_aws
    from azurePolicyEntry import parse_policy as parse_azure
    from policyTree import validate_tree

# Service-level namespaces. This is a starting table, not a complete catalogue.
SERVICE_MAP = {
    'autoscaling': 'Microsoft.Compute',
    'cloudwatch': 'Microsoft.Insights',
    'ec2': 'Microsoft.Compute',
    'elasticloadbalancing': 'Microsoft.Network',
    'iam': 'Microsoft.Authorization',
    'lambda': 'Microsoft.Web',
    'logs': 'Microsoft.OperationalInsights',
    's3': 'Microsoft.Storage',
    'secretsmanager': 'Microsoft.KeyVault',
}

READ_PREFIXES = ('Describe', 'List', 'Get', 'Read', 'View')
WRITE_PREFIXES = ('Create', 'Put', 'Update', 'Attach', 'Detach', 'Enable', 'Disable',
                  'Set', 'Add', 'Modify', 'Write', 'Start', 'Stop', 'Restart',
                  'Reboot', 'Run', 'Terminate')
DELETE_PREFIXES = ('Delete', 'Remove')

UNTRANSLATED_FIELDS = ('NotAction', 'NotResource', 'Principal', 'NotPrincipal')


def map_action(action):
    """Map one AWS action to an Azure action pattern, or None when unknown."""
    if not isinstance(action, str) or ':' not in action:
        return None
    service, verb = action.split(':', 1)
    namespace = SERVICE_MAP.get(service)
    if namespace is None or not verb:
        return None
    if verb == '*':
        return f'{namespace}/*'
    if verb.startswith(READ_PREFIXES):
        return f'{namespace}/*/read'
    if verb.startswith(DELETE_PREFIXES):
        return f'{namespace}/*/delete'
    if verb.startswith(WRITE_PREFIXES):
        return f'{namespace}/*/write'
    return None


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


def translate(aws_tree, *, name=None):
    """Return ``(azure_document, report)`` for an AWS policy tree.

    The report records what mapped, what did not, and the approximations that
    make the result a starting point rather than an equivalence proof.
    """
    document = emit_aws(aws_tree)
    statements = document.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError('AWS policy has no statements to translate')

    actions, not_actions = [], []
    report = {'mapped': {}, 'unmapped': [], 'warnings': [], 'resources': []}
    for statement in statements:
        effect = statement['Effect']
        for action in _values(statement.get('Action')):
            mapped = map_action(action)
            if mapped is None:
                report['unmapped'].append(action)
                continue
            report['mapped'][action] = mapped
            (actions if effect == 'Allow' else not_actions).append(mapped)
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

    candidate = aws_tree.get('name')
    role_name = name or (candidate if candidate and candidate != 'Statement'
                         else 'Translated AWS policy')
    role = {
        'roleName': role_name,
        'description': 'Best-effort translation of an AWS IAM policy into an '
                       'Azure RBAC role definition (service-level action mapping).',
        'permissions': [{'actions': _dedupe(actions),
                         'notActions': _dedupe(not_actions),
                         'dataActions': [],
                         'notDataActions': []}],
        'assignableScopes': ['/'],
    }
    parse_azure(role)
    return role, report


def translate_tree(aws_tree, *, name=None):
    """Return the Azure policy tree for a translated AWS policy tree."""
    document, report = translate(aws_tree, name=name)
    tree = parse_azure(json.dumps(document))
    validate_tree(tree)
    return tree, report


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
