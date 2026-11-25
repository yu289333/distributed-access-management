"""Parse Azure RBAC role definitions and Azure Policy applicability rules."""

import json

from ...policyDocument import load_document
from ...policyTree import make_node, validate_tree
from ...conditions.source import attach_json_source



def _rbac_tree(document, name):
    # REST has properties.permissions, CLI has permissions, PowerShell has Actions.
    fields = {key.lower(): value for key, value in document.items()}
    blocks = fields.get('permissions')
    if blocks is None and any(key in fields for key in ('actions', 'dataactions')):
        blocks = [document]
    if not isinstance(blocks, list) or not blocks:
        raise ValueError('Azure role requires a nonempty permissions array or Actions/DataActions')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'Azure', 'Microsoft.Authorization/roleDefinitions', operator, **kwargs)

    groups = []
    for index, block in enumerate(blocks, 1):
        if not isinstance(block, dict):
            raise ValueError('Each Azure permissions entry must be an object')
        permission = {key.lower(): value for key, value in block.items()}
        if not any(key in permission for key in ('actions', 'dataactions')):
            raise ValueError('Azure permissions entry must contain actions or dataActions')
        planes = []
        for include, exclude in (('actions', 'notActions'), ('dataActions', 'notDataActions')):
            parts = []
            for key in (include, exclude):
                values = permission.get(key.lower(), [])
                if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                    raise ValueError(f'Azure {key} must be a list of nonempty strings')
                matches = node(key, 'OR', children=[node(key, condition_json={key: values})]
                               if values else [])
                parts.append(matches if key == include else
                             node(f'Exclude {key}', 'NOT', children=[matches]))
            planes.append(node(include + ' minus ' + exclude, children=parts))
        grant = node(f'Permission block {index}', 'OR', children=planes,
                     condition_raw=json.dumps(block))
        if 'condition' in permission:
            condition = permission['condition']
            if not isinstance(condition, str) or not condition:
                raise ValueError('Azure permission condition must be nonempty text')
            grant = node(f'Conditional permission block {index}', children=[
                grant, node('Permission condition', condition_json={
                    'condition': condition, 'conditionVersion': permission.get('conditionversion')})])
        groups.append(grant)
    if 'assignablescopes' not in fields:
        return node(name, 'OR', children=groups)
    scopes = fields['assignablescopes']
    if not isinstance(scopes, list) or not all(isinstance(scope, str) and scope for scope in scopes):
        raise ValueError('Azure assignableScopes must be a list of nonempty strings')
    return node(name, children=[node('permissions', 'OR', children=groups),
                                node('assignableScopes', condition_json={'assignableScopes': scopes},
                                     condition_raw=json.dumps({'assignableScopes': scopes}))])



def _rule_tree(rule, name):
    if not isinstance(rule, dict) or set(rule) != {'if', 'then'}:
        raise ValueError('Azure policyRule requires if and then')
    then = rule['then']
    if not isinstance(then, dict) or not isinstance(then.get('effect'), str) or not then['effect']:
        raise ValueError('Azure policyRule.then requires an effect')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'Azure', 'Microsoft.Authorization/policyDefinitions', operator, **kwargs)

    def condition(expression):
        if not isinstance(expression, dict) or not expression:
            raise ValueError('Azure Policy conditions must be nonempty objects')
        logical = set(expression) & {'allOf', 'anyOf', 'not'}
        if logical:
            if len(expression) != 1:
                raise ValueError('Azure logical conditions must have exactly one operator')
            key = next(iter(logical))
            value = expression[key]
            if key == 'not':
                return node('not', 'NOT', children=[condition(value)])
            if not isinstance(value, list) or not value:
                raise ValueError(f'Azure {key} requires a nonempty condition array')
            return node(key, 'AND' if key == 'allOf' else 'OR',
                        children=[condition(child) for child in value])
        return node(
            'Azure condition', condition_json=expression,
            condition_raw=json.dumps(expression)[1:-1])

    def outcome_fields(mapping):
        children = []
        for key, value in mapping.items():
            if isinstance(value, dict) and value:
                children.append(node(key, children=outcome_fields(value)))
            else:
                expression = {key: value}
                leaf = node(key, condition_json=expression,
                            condition_raw=json.dumps(expression)[1:-1])
                children.append(leaf)
        return children

    outcome = node('then', children=outcome_fields(then))
    return node(name, children=[condition(rule['if']), outcome])


def parse_policy(source, name=None):
    """Parse an Azure RBAC role or Azure Policy definition into a policy tree."""
    original = load_document(source)
    document = original.get('properties', original)
    if not isinstance(document, dict):
        raise ValueError('Azure properties must be an object')
    fields = {key.lower(): value for key, value in document.items()}
    label = name or original.get('id') or fields.get('id') or original.get('name') or fields.get('name') or fields.get('rolename') or fields.get('displayname') or 'Azure policy'
    if 'policyrule' in fields:
        label = name or original.get('id') or fields.get('id') or (
            ('\"mode\": ' + json.dumps(fields['mode']) + ' ') if 'mode' in fields else ''
        ) + '\"policyRule\"'
        root = _rule_tree(fields['policyrule'], label)
    else:
        root = _rbac_tree(document, label)
    root['display_name'] = fields.get('rolename') or fields.get('displayname') or fields.get('name')
    if fields.get('description'):
        root['comment'] = '"description": ' + json.dumps(fields['description'])
    root['condition_raw'] = source if isinstance(source, str) else json.dumps(original)
    attach_json_source(root, source)
    validate_tree(root)
    return root
