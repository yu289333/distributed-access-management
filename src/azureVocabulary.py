"""Azure adapter: neutral atoms to Azure RBAC actions and role documents."""

import json

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.azurePolicyEntry import parse_policy

DOMAIN_NAMESPACES = {
    'compute': 'Microsoft.Compute',
    'identity': 'Microsoft.Authorization',
    'logging': 'Microsoft.OperationalInsights',
    'monitoring': 'Microsoft.Insights',
    'network': 'Microsoft.Network',
    'secrets': 'Microsoft.KeyVault',
    'serverless': 'Microsoft.Web',
    'storage': 'Microsoft.Storage',
}

DESCRIPTION = ('Best-effort translation of an AWS IAM policy into an Azure RBAC '
               'role definition (service-level action mapping).')


def encode(neutral):
    """Encode a neutral atom as an Azure action pattern."""
    namespace = DOMAIN_NAMESPACES.get(neutral['domain'])
    if namespace is None:
        raise ValueError(f'Unsupported Azure action domain: {neutral["domain"]}')
    if neutral['verb'] == 'all':
        return f'{namespace}/*'
    return f'{namespace}/*/{neutral["verb"]}'


def build(name, actions, not_actions):
    """Build a custom role definition and verify it parses back."""
    role = {
        'roleName': name,
        'description': DESCRIPTION,
        'permissions': [{'actions': list(actions),
                         'notActions': list(not_actions),
                         'dataActions': [],
                         'notDataActions': []}],
        'assignableScopes': ['/'],
    }
    parse_policy(json.dumps(role))
    return role
