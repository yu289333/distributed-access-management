"""Parse GCP IAM policy documents into schema-compatible policy trees."""

import json

if __package__:
    from .policyTree import load_document, make_node, run_cli, validate_tree
else:
    from policyTree import load_document, make_node, run_cli, validate_tree


def _check_binding(binding, index):
    prefix = f'Binding {index}'
    if not isinstance(binding, dict):
        raise ValueError(f'{prefix} must be an object')
    role = binding.get('role')
    if not isinstance(role, str) or not role:
        raise ValueError(f'{prefix} requires a nonempty role')
    members = binding.get('members')
    if (not isinstance(members, list) or not members or
            not all(isinstance(member, str) and member for member in members)):
        raise ValueError(f'{prefix} requires a nonempty members array of strings')
    if 'condition' in binding:
        condition = binding['condition']
        if (not isinstance(condition, dict) or
                not isinstance(condition.get('expression'), str) or
                not condition['expression']):
            raise ValueError(f'{prefix} condition requires a nonempty expression')


def parse_policy(source, name=None, *, provider_detail='iam.googleapis.com'):
    """Parse a GCP IAM policy into a union of role/member/condition bindings.

    Each binding is an AND of one role, any of its members, and (when present)
    its IAM condition. Condition objects, including their CEL expression text,
    are kept intact in the leaves; no condition translation is attempted.
    """
    original = load_document(source)
    document = original
    if 'bindings' not in document:
        for wrapper in ('policy', 'Policy'):
            if isinstance(document.get(wrapper), dict):
                document = load_document(document[wrapper])
                break
    bindings = document.get('bindings')
    if not isinstance(bindings, list) or not bindings:
        raise ValueError('GCP policy requires a nonempty bindings array')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'GCP', provider_detail, operator, **kwargs)

    groups = []
    for index, binding in enumerate(bindings, 1):
        _check_binding(binding, index)
        parts = [
            node('Role', condition_json={'role': binding['role']}),
            node('Members', 'OR', children=[
                node(member, condition_json={'member': member})
                for member in binding['members']]),
        ]
        if 'condition' in binding:
            parts.append(node('IAM condition', condition_json={
                'condition': binding['condition']}))
        groups.append(node(f'Binding {index}', children=parts,
                           condition_raw=json.dumps(binding)))

    policy_name = name or document.get('name') or original.get('name') or 'GCP IAM policy'
    root = node(policy_name, 'OR', children=groups,
                condition_raw=source if isinstance(source, str) else json.dumps(original))
    validate_tree(root)
    return root


def main(argv=None):
    return run_cli(parse_policy, argv)


if __name__ == '__main__':
    raise SystemExit(main())
