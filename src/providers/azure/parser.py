"""Parse Azure RBAC role definitions and Azure Policy applicability rules."""

import json

from ...policyDocument import load_document
from ...policyTree import make_node, validate_tree
from ...conditions.source import attach_json_source



RBAC_DETAIL = 'Microsoft.Authorization/roleDefinitions'
POLICY_DETAIL = 'Microsoft.Authorization/policyDefinitions'
POLICY_ASSIGNMENT_DETAIL = 'Microsoft.Authorization/policyAssignments'
DENY_ASSIGNMENT_DETAIL = 'Microsoft.Authorization/denyAssignments'
PERMISSION_FIELDS = ('actions', 'notActions', 'dataActions', 'notDataActions')


def _rbac_tree(document, name, detail=RBAC_DETAIL):
    # REST has properties.permissions, CLI has permissions, PowerShell has Actions.
    fields = {key.lower(): value for key, value in document.items()}
    blocks = fields.get('permissions')
    if blocks is None and any(key in fields for key in ('actions', 'dataactions')):
        blocks = [document]
    if not isinstance(blocks, list) or not blocks:
        raise ValueError('Azure role requires a nonempty permissions array or Actions/DataActions')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'Azure', detail, operator, **kwargs)

    groups = []
    for index, block in enumerate(blocks, 1):
        if not isinstance(block, dict):
            raise ValueError('Each Azure permissions entry must be an object')
        permission = {key.lower(): value for key, value in block.items()}
        if not any(key in permission for key in ('actions', 'dataactions')):
            raise ValueError('Azure permissions entry must contain actions or dataActions')
        leaves = []
        for key in PERMISSION_FIELDS:
            if key.lower() not in permission:
                continue
            values = permission[key.lower()]
            if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
                raise ValueError(f'Azure {key} must be a list of nonempty strings')
            leaves.append(node(key, condition_json={key: values}))
        grant = node(f'Permission block {index}', 'AND', children=leaves,
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



def _policy_assignment_tree(original, fields, name):
    scope = fields.get('scope', original.get('scope'))
    excluded = fields.get('notscopes', [])
    if not isinstance(scope, str) or not scope:
        raise ValueError('Azure Policy assignment requires an explicit scope')
    if not isinstance(excluded, list) or not all(isinstance(value, str) and value for value in excluded):
        raise ValueError('Azure notScopes must be a list of nonempty strings')

    def node(label, **kwargs):
        return make_node(label, 'Azure', POLICY_ASSIGNMENT_DETAIL, **kwargs)

    return node(name, children=[
        node('scope', condition_json={'scope': scope}),
        node('notScopes', condition_json={'notScopes': excluded}),
    ])


def _deny_assignment_tree(fields, name):
    principals = fields.get('principals')
    excluded = fields.get('excludeprincipals', [])
    for key, values in (('principals', principals), ('excludePrincipals', excluded)):
        if not isinstance(values, list) or any(
                not isinstance(value, dict) or not isinstance(value.get('id'), str)
                or not value['id'] for value in values):
            raise ValueError(f'Azure {key} must be a list of principal objects with IDs')
    if not principals:
        raise ValueError('Azure deny assignment requires at least one principal')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'Azure', DENY_ASSIGNMENT_DETAIL, operator, **kwargs)

    permissions = _rbac_tree({'permissions': fields.get('permissions')},
                             'permissions', detail=DENY_ASSIGNMENT_DETAIL)
    return node(name, 'AND', children=[
        permissions,
        node('principals', condition_json={'principals': principals}),
        node('excludePrincipals', condition_json={'excludePrincipals': excluded}),
    ])


def _rule_tree(rule, name):
    if not isinstance(rule, dict) or set(rule) != {'if', 'then'}:
        raise ValueError('Azure policyRule requires if and then')
    then = rule['then']
    if not isinstance(then, dict) or not isinstance(then.get('effect'), str) or not then['effect']:
        raise ValueError('Azure policyRule.then requires an effect')

    def node(label, operator='AND', **kwargs):
        return make_node(label, 'Azure', POLICY_DETAIL, operator, **kwargs)

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
    """Parse an Azure role, policy definition, or supported assignment."""
    original = load_document(source)
    document = original.get('properties', original)
    if not isinstance(document, dict):
        raise ValueError('Azure properties must be an object')
    fields = {key.lower(): value for key, value in document.items()}
    label = name or original.get('id') or fields.get('id') or original.get('name') or fields.get('name') or fields.get('rolename') or fields.get('displayname') or 'Azure policy'
    kind = str(original.get('type', '')).lower()
    if kind == POLICY_ASSIGNMENT_DETAIL.lower() or 'policydefinitionid' in fields:
        root = _policy_assignment_tree(original, fields, label)
    elif kind == DENY_ASSIGNMENT_DETAIL.lower() or ('principals' in fields and 'permissions' in fields):
        root = _deny_assignment_tree(fields, label)
    elif 'policyrule' in fields:
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
