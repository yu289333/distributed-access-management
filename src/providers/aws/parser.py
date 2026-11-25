"""Parse AWS IAM policies into source-preserving field trees."""

import json

from ...policyDocument import load_document
from ...policyTree import make_node, validate_tree
from ...conditions.source import attach_json_source



def _string_values(value):
    return (isinstance(value, str) and bool(value) or
            isinstance(value, list) and bool(value) and
            all(isinstance(item, str) and item for item in value))


def _check_statement(statement, index):
    prefix = f'Statement {index}'
    if not isinstance(statement, dict) or statement.get('Effect') not in ('Allow', 'Deny'):
        raise ValueError(f'{prefix} must be an object with Effect Allow or Deny')
    if 'Sid' in statement and not isinstance(statement['Sid'], str):
        raise ValueError(f'{prefix} Sid must be text')
    for positive, negative in (('Action', 'NotAction'), ('Resource', 'NotResource'),
                               ('Principal', 'NotPrincipal')):
        keys = [key for key in (positive, negative) if key in statement]
        if len(keys) == 2 or positive == 'Action' and not keys:
            raise ValueError(f'{prefix} requires mutually exclusive {positive}/{negative}')
        for key in keys:
            value = statement[key]
            if positive == 'Principal':
                valid = value == '*' or (isinstance(value, dict) and bool(value) and
                                        all(_string_values(v) for v in value.values()))
            else:
                valid = _string_values(value)
            if not valid:
                raise ValueError(f'{prefix} has invalid {key}')
    # Trust policies describe a role implicitly, so may omit Resource.
    if not any(key in statement for key in
               ('Resource', 'NotResource', 'Principal', 'NotPrincipal')):
        raise ValueError(f'{prefix} requires a resource or trust-policy principal')
    if 'Condition' in statement and not isinstance(statement['Condition'], dict):
        raise ValueError(f'{prefix} Condition must be an object')


def parse_policy(source, name=None, *, provider_detail='arn:aws'):
    """Parse AWS statement groups, separating declared Deny statements when present."""
    original = load_document(source)
    document = original
    if 'Statement' not in document and 'PolicyVersion' in document:
        document = load_document(document['PolicyVersion'])
    if 'Statement' not in document:
        for wrapper in ('Document', 'PolicyDocument'):
            if wrapper in document:
                document = load_document(document[wrapper])
                break
    statements = document.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError('AWS policy requires a nonempty Statement object or array')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'AWS', provider_detail, operator, **kwargs)

    allowed, denied = [], []
    for index, statement in enumerate(statements, 1):
        _check_statement(statement, index)
        group = node(statement.get('Sid') or f'Statement {index}', children=[
            node(key, condition_json={key: value},
                 condition_raw=json.dumps({key: value}))
            for key, value in statement.items() if key != 'Sid'
        ], condition_raw=json.dumps(statement))
        if 'Sid' in statement:
            group['display_name'] = '"Sid": ' + json.dumps(statement['Sid'])
        (denied if statement['Effect'] == 'Deny' else allowed).append(group)

    policy_name = name or original.get('PolicyName') or original.get('Arn') or document.get('Id') or 'Statement'
    operator = 'OR'
    children = allowed
    if denied:
        operator = 'SUBTRACT'
        children = [
            node('Allow statements', 'OR', children=allowed, child_position=0),
            node('Deny statements', 'OR', children=denied, child_position=1),
        ]
    root = node(policy_name, operator, children=children,
                condition_raw=source if isinstance(source, str) else json.dumps(original))
    if 'Version' in document:
        root['display_name'] = '"Version": ' + json.dumps(document['Version'])
    attach_json_source(root, source)
    validate_tree(root)
    return root
