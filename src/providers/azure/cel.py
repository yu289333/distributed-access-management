"""Azure source-preserving condition expressions."""
from ...conditions.format import literal, join


def azure(expression, detail):
    if detail == 'Microsoft.Authorization/policyDefinitions' and 'field' not in expression:
        return ' && '.join(f'{key} == {literal(value)}' for key, value in expression.items())
    if detail == 'Microsoft.Authorization/roleDefinitions':
        parts = []
        for key, value in expression.items():
            if key == 'assignableScopes':
                if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                    raise ValueError('assignableScopes requires a string list')
                parts.append('assignableScopes == ' + literal(value))
                continue
            if key.lower() not in ('actions', 'notactions', 'dataactions', 'notdataactions'):
                raise ValueError(f'Unsupported Azure RBAC field: {key}')
            if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                raise ValueError(f'{key} requires a string list')
            parts.append(f'{key} == {literal(value)}')
        return parts[0] if len(parts) == 1 else join(parts)
    if detail != 'Microsoft.Authorization/policyDefinitions' or set(expression) not in (
            {'field', 'equals'}, {'field', 'notEquals'}, {'field', 'exists'}):
        raise ValueError('Unsupported Azure Policy condition')
    key = expression['field']
    if not isinstance(key, str) or '[*]' in key:
        raise ValueError('Azure array aliases require provider evaluation')
    target = key  # Preserve the source alias verbatim for the requested display format.
    if 'exists' in expression:
        value = expression['exists']
        if type(value) not in (bool, str) or value not in (True, False, 'true', 'false'):
            raise ValueError('Invalid Azure exists value')
        return f'has(resource.{target})' if value in (True, 'true') else f'!has(resource.{target})'
    value = expression.get('equals', expression.get('notEquals'))
    if isinstance(value, str) and value.startswith('['):
        raise ValueError('Azure template expressions require provider evaluation')
    operator = '!=' if 'notEquals' in expression else '=='
    return f'{target} {operator} {literal(value)}'
