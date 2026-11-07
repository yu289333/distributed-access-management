"""Parse AWS IAM policy documents into schema-compatible policy trees."""

import json

if __package__:
    from .policyTree import load_document, make_node, run_cli, validate_tree
else:
    from policyTree import load_document, make_node, run_cli, validate_tree


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
        leaf = node(statement.get('Sid') or f'Statement {index}',
                    condition_json=statement, condition_raw=json.dumps(statement))
        (allows if statement['Effect'] == 'Allow' else denies).append(leaf)

    policy_name = name or original.get('PolicyName') or original.get('Arn') or document.get('Id') or 'AWS policy'
    root = node(policy_name, 'OR', children=allows,
                condition_raw=source if isinstance(source, str) else json.dumps(original))
    if denies:
        root['operator'] = 'AND'
        root['children'] = [node('Allowed statements', 'OR', children=allows),
                            node('Exclude explicit denies', 'NOT', children=[
                                node('Denied statements', 'OR', children=denies)])]
    validate_tree(root)
    return root


def main(argv=None):
    return run_cli(parse_policy, argv)


if __name__ == '__main__':
    raise SystemExit(main())
