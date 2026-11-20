"""Parse AWS IAM policies into field trees with source-preserving expressions.

Condition expressions compare original field values, preserving case, lists,
wildcards and nested objects. Allow/deny composition stays in the tree.
"""

import json

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.conditionExpression import populate_condition_cel
from src.policyDocument import load_document
from src.policyTree import make_node, validate_tree
from src.policyCli import run_cli
from src.conditionSource import attach_json_source



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
    """Parse an AWS JSON policy into an allow-set minus an explicit-deny-set."""
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

    allows, denies = [], []
    for index, statement in enumerate(statements, 1):
        _check_statement(statement, index)
        group = node(statement.get('Sid') or f'Statement {index}', children=[
            node(key, condition_json={key: value},
                 condition_raw=json.dumps({key: value}))
            for key, value in statement.items() if key != 'Sid'
        ], condition_raw=json.dumps(statement))
        if 'Sid' in statement:
            group['display_name'] = '"Sid": ' + json.dumps(statement['Sid'])
        (allows if statement['Effect'] == 'Allow' else denies).append(group)

    policy_name = name or original.get('PolicyName') or original.get('Arn') or document.get('Id') or 'Statement'
    root = node(policy_name, 'OR', children=allows,
                condition_raw=source if isinstance(source, str) else json.dumps(original))
    if denies:
        root['operator'] = 'AND'
        root['children'] = [node('Allowed statements', 'OR', children=allows),
                            node('Exclude explicit denies', 'NOT', children=[
                                node('Denied statements', 'OR', children=denies)])]
    if 'Version' in document:
        root['display_name'] = '"Version": ' + json.dumps(document['Version'])
    populate_condition_cel(root)
    attach_json_source(root, source)
    validate_tree(root)
    return root


def main(argv=None):
    return run_cli(parse_policy, argv)


if __name__ == '__main__':
    raise SystemExit(main())
