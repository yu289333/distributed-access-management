"""Reconstruct an Azure role, policy definition, or assignment from a policy tree.

This is the outbound half of the Azure morph. It accepts a tree produced by
``azurePolicyEntry.parse_policy`` (or the same tree read back from the database)
and returns the original Azure JSON document. It is deliberately narrow:

* only Azure trees are accepted; an AWS or GCP tree is not a cross-cloud input,
* the outer metadata (id, name, description, parameters, mode, ...) is recovered
  from the root's ``condition_raw``; the permissions or ``policyRule`` are rebuilt
  from the tree, so edits to leaves are reflected,
* supported shapes include role definitions, policy definitions, policy
  assignments with an explicit scope, and RBAC deny assignments.
"""

from copy import deepcopy

from ...policyCli import run_emit_cli
from ...policyTree import validate_tree
from ..common import check_provider, read_raw
from .parser import (
    DENY_ASSIGNMENT_DETAIL, PERMISSION_FIELDS, POLICY_ASSIGNMENT_DETAIL, POLICY_DETAIL, RBAC_DETAIL,
)


def _container(document):
    properties = document.get('properties')
    return properties if isinstance(properties, dict) else document


def _scopes(root):
    for child in root.get('children', []):
        expression = child.get('condition_json')
        if isinstance(expression, dict) and 'assignableScopes' in expression:
            return expression['assignableScopes']
    return None


def _blocks(root):
    children = root.get('children', [])
    if root.get('operator_onChildren') == 'AND' and children and children[0].get('name') == 'permissions':
        return children[0].get('children', [])
    if root.get('operator_onChildren') == 'OR':
        return children
    raise ValueError('Unexpected Azure RBAC tree shape')


def _leaf_values(node, key):
    values = []
    for child in node.get('children', []):
        expression = child.get('condition_json')
        if not isinstance(expression, dict) or key not in expression:
            raise ValueError(f'Expected {key} leaves below {node.get("name")!r}')
        value = expression[key]
        values.extend(value if isinstance(value, list) else [value])
    return values


def _block(node, original):
    condition = condition_version = None
    if node.get('name', '').startswith('Conditional permission block'):
        grant, condition_node = node.get('children', [])
        expression = condition_node.get('condition_json') or {}
        condition = expression.get('condition')
        condition_version = expression.get('conditionVersion')
        node = grant
    permission = {}
    for plane in node.get('children', []):
        expression = plane.get('condition_json')
        if expression is not None:
            key = plane.get('name')
            if not isinstance(expression, dict) or set(expression) != {key}:
                raise ValueError(f'Unexpected Azure permission leaf: {key!r}')
            value = expression[key]
            if key in PERMISSION_FIELDS and not isinstance(value, list):
                raise ValueError(f'Azure {key} must be a list')
            permission[key] = deepcopy(value)
            continue
        include, exclude = plane.get('name', '').split(' minus ')
        parts = plane.get('children', [])
        if len(parts) != 2:
            raise ValueError(f'Unexpected Azure permission plane: {plane.get("name")!r}')
        # Old exports wrap the exclusion group in a NOT node.
        included, negated = parts
        excluded = negated['children'][0] if negated.get('children') else negated
        for operand, key in ((included, include), (excluded, exclude)):
            values = _leaf_values(operand, key)
            if values or key in original:
                permission[key] = values
    if condition is not None:
        permission['condition'] = condition
    if condition_version is not None:
        permission['conditionVersion'] = condition_version
    return permission


def _condition(node):
    expression = node.get('condition_json')
    if expression is not None:
        return deepcopy(expression)
    name = node.get('name')
    children = node.get('children', [])
    if name == 'allOf':
        return {'allOf': [_condition(child) for child in children]}
    if name == 'anyOf':
        return {'anyOf': [_condition(child) for child in children]}
    if name == 'not' and len(children) == 1:
        return {'not': _condition(children[0])}
    raise ValueError(f'Unexpected Azure Policy condition node: {name!r}')


def _outcome(node):
    result = {}
    for child in node.get('children', []):
        expression = child.get('condition_json')
        if expression is not None:
            result.update(deepcopy(expression))
        else:
            result[child['name']] = _outcome(child)
    return result


def _permission_blocks(nodes, container):
    original_blocks = container.get('permissions')
    if not isinstance(original_blocks, list):
        original_blocks = []
    blocks = []
    for index, node in enumerate(nodes):
        template = {}
        if index < len(original_blocks) and isinstance(original_blocks[index], dict):
            template = deepcopy(original_blocks[index])
        template.update(_block(node, template))
        blocks.append(template)
    return blocks


def _emit_rbac(tree, document):
    container = _container(document)
    blocks = _permission_blocks(_blocks(tree), container)

    scopes = _scopes(tree)
    if 'Actions' in document:
        block = blocks[0] if blocks else {}
        for key, upper in zip(('actions', 'notActions', 'dataActions', 'notDataActions'),
                              ('Actions', 'NotActions', 'DataActions', 'NotDataActions')):
            if key in block or upper in document:
                document[upper] = block.get(key, [])
        for key, value in block.items():
            if key.lower() not in {'actions', 'notactions', 'dataactions', 'notdataactions'}:
                document[key] = value
        if scopes is not None:
            document['AssignableScopes'] = scopes
    elif isinstance(document.get('properties'), dict):
        container['permissions'] = blocks
        if scopes is not None:
            container['assignableScopes'] = scopes
    else:
        document['permissions'] = blocks
        if scopes is not None:
            document['assignableScopes'] = scopes
    return document


def _emit_policy_definition(tree, document):
    children = tree.get('children', [])
    if len(children) != 2 or children[1].get('name') != 'then':
        raise ValueError('Unexpected Azure Policy tree shape')
    _container(document)['policyRule'] = {
        'if': _condition(children[0]),
        'then': _outcome(children[1]),
    }
    return document


def _emit_policy_assignment(tree, document):
    children = tree.get('children', [])
    fields = {child.get('name'): child for child in children}
    if (tree.get('operator_onChildren') != 'AND' or len(children) != 2
            or set(fields) != {'scope', 'notScopes'}):
        raise ValueError('Unexpected Azure Policy assignment tree shape')

    scope = fields['scope'].get('condition_json')
    excluded = fields['notScopes'].get('condition_json')
    if not isinstance(scope, dict) or not isinstance(scope.get('scope'), str) or not scope['scope']:
        raise ValueError('Azure Policy assignment requires an explicit scope')
    if not isinstance(excluded, dict) or not isinstance(excluded.get('notScopes'), list):
        raise ValueError('Expected an Azure Policy assignment notScopes array')
    container = _container(document)
    target = document if 'scope' in document and 'scope' not in container else container
    target['scope'] = scope['scope']
    not_scopes = excluded['notScopes']
    if not_scopes or 'notScopes' in container:
        container['notScopes'] = deepcopy(not_scopes)
    return document


def _emit_deny_assignment(tree, document):
    children = tree.get('children', [])
    fields = {child.get('name'): child for child in children}
    if (tree.get('operator_onChildren') != 'AND' or len(children) != 3
            or set(fields) != {'permissions', 'principals', 'excludePrincipals'}):
        raise ValueError('Unexpected Azure deny assignment tree shape')

    container = _container(document)
    container['permissions'] = _permission_blocks(_blocks(fields['permissions']), container)
    for key in ('principals', 'excludePrincipals'):
        expression = fields[key].get('condition_json')
        if not isinstance(expression, dict) or not isinstance(expression.get(key), list):
            raise ValueError(f'Expected an Azure deny assignment {key} array')
        if key == 'principals' or expression[key] or key in container:
            container[key] = deepcopy(expression[key])
    return document


def emit_policy(tree):
    """Return the Azure document reconstructed from an Azure policy tree."""
    validate_tree(tree, check_source=False)
    check_provider(tree, 'Azure')
    document = read_raw(tree)
    detail = tree.get('provider_detail')
    if detail == POLICY_DETAIL:
        return _emit_policy_definition(tree, document)
    if detail == POLICY_ASSIGNMENT_DETAIL:
        return _emit_policy_assignment(tree, document)
    if detail == DENY_ASSIGNMENT_DETAIL:
        return _emit_deny_assignment(tree, document)
    if detail not in (RBAC_DETAIL, None):
        raise ValueError(f'Unsupported Azure provider_detail: {detail}')
    return _emit_rbac(tree, document)


emit_azure = emit_policy


def main(argv=None):
    return run_emit_cli('Rebuild an Azure role, policy definition, or assignment from a policy tree', emit_policy, argv)


if __name__ == '__main__':
    raise SystemExit(main())
