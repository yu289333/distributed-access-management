"""Parse GCP IAM policy documents into schema-compatible policy trees."""

import json

from ...document import load_document
from ...tree import make_node, validate_tree
from ...conditions.source import attach_json_source


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


def _bindings_tree(node, name, bindings):
    if not isinstance(bindings, list) or not bindings:
        raise ValueError('GCP policy requires a nonempty bindings array')
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
    return node(name, 'OR', children=groups)


def _check_access_rule(rule, index):
    prefix = f'GCP Unified Access Policy rule {index}'
    if not isinstance(rule, dict) or rule.get('effect') not in ('ALLOW', 'DENY'):
        raise ValueError(f'{prefix} must be an object with effect ALLOW or DENY')
    principals = rule.get('principals')
    if not isinstance(principals, list) or not principals or any(
            not isinstance(principal, str) or not principal for principal in principals):
        raise ValueError(f'{prefix} requires a nonempty principals array of strings')
    if not isinstance(rule.get('operation'), dict):
        raise ValueError(f'{prefix} requires an operation object')


def _has_access_rules(document):
    details = document.get('details')
    return isinstance(details, dict) and 'rules' in details


def _access_policy_tree(node, name, rules):
    if not isinstance(rules, list) or not rules:
        raise ValueError('GCP Unified Access Policy requires a nonempty details.rules array')
    groups = {'ALLOW': [], 'DENY': []}
    for position, rule in enumerate(rules):
        _check_access_rule(rule, position + 1)
        leaves = [node(key, condition_json={key: value}) for key, value in rule.items()]
        groups[rule['effect']].append(node(
            f'Rule {position + 1}', children=leaves, child_position=position,
            condition_raw=json.dumps(rule)))
    return node(name, 'AND', children=[
        node('ALLOW rules', 'OR', children=groups['ALLOW']),
        node('Exclude DENY rules', 'NOT', children=[
            node('DENY rules', 'OR', children=groups['DENY']),
        ]),
    ])


def parse_policy(source, name=None, *, provider_detail='iam.googleapis.com'):
    """Parse IAM allow bindings or REST Unified Access Policy rules."""
    original = load_document(source)
    document = original
    if 'bindings' not in document and not _has_access_rules(document):
        for wrapper in ('policy', 'Policy'):
            if isinstance(document.get(wrapper), dict):
                document = load_document(document[wrapper])
                break

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'GCP', provider_detail, operator, **kwargs)

    policy_name = name or document.get('name') or original.get('name')
    if 'bindings' not in document and _has_access_rules(document):
        root = _access_policy_tree(node, policy_name or document.get('displayName')
                                   or 'GCP Unified Access Policy', document['details']['rules'])
    else:
        root = _bindings_tree(node, policy_name or 'GCP IAM policy', document.get('bindings'))
    root['condition_raw'] = source if isinstance(source, str) else json.dumps(original)
    attach_json_source(root, source)
    validate_tree(root)
    return root
