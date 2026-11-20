"""AWS source-preserving condition expressions."""
from .conditionFormat import literal, join


def aws(expression):
    """Preserve IAM field names and values; do not evaluate IAM request matching."""
    supported = {'Effect', 'Sid', 'Action', 'NotAction', 'Resource', 'NotResource',
                 'Principal', 'NotPrincipal', 'Condition'}
    parts = []
    for key, value in expression.items():
        if key not in supported:
            raise ValueError(f'Unsupported AWS field: {key}')
        if key == 'Effect' and value not in ('Allow', 'Deny'):
            raise ValueError('Invalid AWS effect')
        parts.append(f'{key} == {literal(value)}')
    return parts[0] if len(parts) == 1 else join(parts)
