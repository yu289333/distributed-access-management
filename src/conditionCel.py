"""Translate supported AWS/Azure leaf predicates into standard CEL booleans."""
import json
import re


def literal(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def join(parts, op='&&'):
    parts = list(parts)
    return ('(' + f' {op} '.join(f'({p})' for p in parts) + ')'
            if parts else ('true' if op == '&&' else 'false'))


def regex_escape(value):
    return ''.join('\\' + c if c in r'\.^$|?*+()[]{}' else c for c in value)


def cel_activation(request, context=None, fields=None, resource=None):
    """Inputs for CEL, including regex-safe IAM policy variable substitution.

    Do not accept regex_context directly from an untrusted caller.
    """
    context = dict(context or {})
    return dict(request=dict(request), context=context, fields=dict(fields or {}),
                resource=dict(resource or {}),
                regex_context={k: regex_escape(v) for k, v in context.items()
                               if isinstance(v, str)})


def patterns(target, values, *, insensitive=False, variables=False, wildcard=True):
    values = [values] if isinstance(values, str) else values
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError('Patterns must be strings')
    alternatives = []
    for value in values:
        fragments, guards = [literal('(?i)^' if insensitive else '^')], []
        for token in re.split(r'(\$\{[^}]+\})', value) if variables else [value]:
            if variables and token.startswith('${') and token.endswith('}'):
                key = literal(token[2:-1])
                guards.append(f'{key} in regex_context')
                fragments.append(f'regex_context[{key}]')
            else:
                fragments.append(literal(''.join(
                    '.*' if c == '*' and wildcard else
                    '.' if c == '?' and wildcard else regex_escape(c) for c in token)))
        fragments.append(literal('$'))
        alternatives.append(join([*guards, f'{target}.matches(' + ' + '.join(fragments) + ')']))
    return join(alternatives, '||')


def aws_condition(condition):
    parts = []
    if not isinstance(condition, dict):
        raise ValueError('Condition must be an object')
    for operator, entries in condition.items():
        optional = operator.endswith('IfExists')
        base = operator[:-8] if optional else operator
        supported = {'Bool', 'Null', 'StringEquals', 'StringNotEquals',
                     'StringEqualsIgnoreCase', 'StringNotEqualsIgnoreCase',
                     'StringLike', 'StringNotLike', 'ArnEquals', 'ArnNotEquals',
                     'ArnLike', 'ArnNotLike'}
        if base not in supported or base == 'Null' and optional:
            raise ValueError(f'Unsupported AWS condition operator: {operator}')
        if not isinstance(entries, dict):
            raise ValueError('Condition operator requires a key/value map')
        for key, values in entries.items():
            present, target = f'{literal(key)} in context', f'context[{literal(key)}]'
            values = values if isinstance(values, list) else [values]
            negative = 'Not' in base
            if base in ('Bool', 'Null'):
                if not values or any(type(v) not in (bool, str) or v not in (True, False, 'true', 'false') for v in values):
                    raise ValueError(f'{base} requires boolean values')
                if base == 'Null':
                    parts.append(join((f'!({present}) || {target} == null' if v in (True, 'true')
                                       else f'{present} && {target} != null' for v in values), '||'))
                    continue
                match = join((f'({target} == {literal(v in (True, "true"))} || '
                              f'{target} == {literal("true" if v in (True, "true") else "false")})'
                              for v in values), '||')
            else:
                match = patterns(target, values, insensitive='IgnoreCase' in base,
                                 variables=True, wildcard='Like' in base or base.startswith('Arn'))
                if negative:
                    match = f'!({match})'
            parts.append(f'!({present}) || ({match})' if optional or negative
                         else f'{present} && ({match})')
    return join(parts)


def aws(expression):
    parts = []
    for key, value in expression.items():
        if key in ('Effect', 'Sid'):
            if key == 'Effect' and value not in ('Allow', 'Deny'):
                raise ValueError('Invalid AWS effect')
            parts.append('true')  # Metadata: allow/deny is implemented by tree structure.
        elif key in ('Action', 'NotAction', 'Resource', 'NotResource'):
            action = key in ('Action', 'NotAction')
            match = patterns('request.action' if action else 'request.resource', value,
                             insensitive=action, variables=not action)
            parts.append(f'!({match})' if key.startswith('Not') else match)
        elif key == 'Condition':
            parts.append(aws_condition(value))
        elif key in ('Principal', 'NotPrincipal'):
            if value == '*':
                match = 'true'
            elif isinstance(value, dict):
                match = join((join([f'request.principal_type == {literal(kind)}',
                                    patterns('request.principal', items, wildcard=False)])
                              for kind, items in value.items()), '||')
            else:
                raise ValueError('Unsupported principal')
            parts.append(f'!({match})' if key == 'NotPrincipal' else match)
        else:
            raise ValueError(f'Unsupported AWS field: {key}')
    return join(parts)


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



def condition_to_cel(condition_json=None, condition_raw=None, *, provider, provider_detail=None):
    if condition_json is None:
        if __package__:
            from .policyTree import load_document
        else:
            from policyTree import load_document
        condition_json = load_document(condition_raw)
    if not isinstance(condition_json, dict) or not condition_json:
        raise ValueError('Condition must be a nonempty object')
    if provider == 'AWS':
        return aws(condition_json)
    if provider == 'Azure':
        return azure(condition_json, provider_detail)
    raise ValueError(f'Unsupported provider: {provider}')


def populate_condition_cel(tree):
    """Fill expression leaves and empty-set constants; annotate unsupported syntax."""
    if tree['children']:
        for child in tree['children']:
            populate_condition_cel(child)
    elif tree['condition_json'] is None and not tree['condition_raw']:
        tree['condition_cel'] = 'false' if tree['operator'] in ('OR', 'XOR') else 'true'
    else:
        try:
            tree['condition_cel'] = condition_to_cel(
                tree['condition_json'], tree['condition_raw'], provider=tree['provider'],
                provider_detail=tree['provider_detail'])
        except ValueError as exc:
            tree['condition_cel'] = None
            note = f'CEL conversion unavailable: {exc}'
            if note not in (tree['comment'] or ''):
                tree['comment'] = '\n'.join(filter(None, [tree['comment'], note]))
    return tree
