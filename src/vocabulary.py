"""Neutral action vocabulary shared by provider adapters.

An atom is the provider-independent meaning of one action: which resource
*domain* it touches and which *verb* it performs. Provider adapters translate
their own action strings to atoms (decode) and atoms back to their own strings
(encode), so a new provider adds two adapters instead of a new translator for
every existing provider.
"""

DOMAINS = ('compute', 'storage', 'network', 'identity', 'logging',
           'monitoring', 'serverless', 'secrets')
VERBS = ('read', 'write', 'delete', 'all')


def atom(domain, verb):
    """Build a neutral action atom; reject unknown domains or verbs."""
    if domain not in DOMAINS:
        raise ValueError(f'Unknown action domain: {domain}')
    if verb not in VERBS:
        raise ValueError(f'Unknown action verb: {verb}')
    return {'domain': domain, 'verb': verb}
