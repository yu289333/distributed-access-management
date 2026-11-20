"""AWS adapter: policy statements and AWS actions to neutral atoms."""

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awsPolicyEmitter import emit_policy
from src.policyStatement import make_statement
from src.vocabulary import atom

# Service-level domains. This is a starting table, not a complete catalogue.
SERVICE_DOMAINS = {
    'autoscaling': 'compute',
    'cloudwatch': 'monitoring',
    'ec2': 'compute',
    'elasticloadbalancing': 'network',
    'iam': 'identity',
    'lambda': 'serverless',
    'logs': 'logging',
    's3': 'storage',
    'secretsmanager': 'secrets',
}

READ_PREFIXES = ('Describe', 'List', 'Get', 'Read', 'View')
WRITE_PREFIXES = ('Create', 'Put', 'Update', 'Attach', 'Detach', 'Enable', 'Disable',
                  'Set', 'Add', 'Modify', 'Write', 'Start', 'Stop', 'Restart',
                  'Reboot', 'Run', 'Terminate')
DELETE_PREFIXES = ('Delete', 'Remove')
UNTRANSLATED_FIELDS = ('NotAction', 'NotResource', 'Principal', 'NotPrincipal')


def decode(action):
    """Decode one AWS action into a neutral atom, or None when unknown."""
    if not isinstance(action, str) or ':' not in action:
        return None
    service, verb = action.split(':', 1)
    domain = SERVICE_DOMAINS.get(service)
    if domain is None or not verb:
        return None
    if verb == '*':
        return atom(domain, 'all')
    if verb.startswith(READ_PREFIXES):
        return atom(domain, 'read')
    if verb.startswith(DELETE_PREFIXES):
        return atom(domain, 'delete')
    if verb.startswith(WRITE_PREFIXES):
        return atom(domain, 'write')
    return None


def read(tree):
    """Return neutral statements for an AWS policy tree."""
    document = emit_policy(tree)
    statements = document.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError('AWS policy has no statements to translate')
    result = []
    for statement in statements:
        untranslated = []
        for field in UNTRANSLATED_FIELDS:
            if field in statement:
                untranslated.extend((field, value) for value in _values(statement[field]))
        result.append(make_statement(
            statement['Effect'].lower(),
            actions=_values(statement.get('Action')),
            resources=_values(statement.get('Resource')),
            conditions=sorted(statement.get('Condition', {})),
            untranslated=untranslated,
        ))
    return result


def _values(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)
