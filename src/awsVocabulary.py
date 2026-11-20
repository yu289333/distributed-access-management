"""AWS adapter: policy statements and AWS actions to neutral atoms."""

import json

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awsPolicyEmitter import emit_policy
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
    """Return the policy statements of an AWS tree, in statement order."""
    document = emit_policy(tree)
    statements = document.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError('AWS policy has no statements to translate')
    return statements


def _values(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)
