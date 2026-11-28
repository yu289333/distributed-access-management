"""CEL expressions for AWS condition leaves."""
from ...conditions.format import join, literal, regex_escape


def aws(expression, provider_detail=None):
    """Express scalar Action globs as matches and preserve other field values."""
    supported = {'Effect', 'Sid', 'Action', 'NotAction', 'Resource', 'NotResource',
                 'Principal', 'NotPrincipal', 'Condition'}
    parts = []
    for key, value in expression.items():
        if key not in supported:
            raise ValueError(f'Unsupported AWS field: {key}')
        if key == 'Effect' and value not in ('Allow', 'Deny'):
            raise ValueError('Invalid AWS effect')
        if key == 'Action' and isinstance(value, str) and '*' in value:
            pattern = '^' + '.*'.join(regex_escape(part) for part in value.split('*')) + '$'
            parts.append(f'{key}.matches({literal(pattern)})')
        else:
            parts.append(f'{key} == {literal(value)}')
    return parts[0] if len(parts) == 1 else join(parts)
