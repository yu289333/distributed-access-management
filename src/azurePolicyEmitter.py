"""Reconstruct an Azure RBAC role or policy definition from a policy tree.

This is the outbound half of the Azure morph. It accepts a tree produced by
``azurePolicyEntry.parse_policy`` (or the same tree read back from the database)
and returns the original Azure JSON document. It is deliberately narrow:

* only Azure trees are accepted; an AWS or GCP tree is not a cross-cloud input,
* the outer metadata (id, name, description, parameters, mode, ...) is recovered
  from the root's ``condition_raw``; the permissions or ``policyRule`` are rebuilt
  from the tree, so edits to leaves are reflected,
* RBAC and policy definitions are the supported shapes; locks, ARM templates,
  initiatives, and assignments are not emitted.
"""

import argparse
import json
from copy import deepcopy
from pathlib import Path

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.policyTree import validate_tree

RBAC_DETAIL = 'Microsoft.Authorization/roleDefinitions'
POLICY_DETAIL = 'Microsoft.Authorization/policyDefinitions'
PLANES = (('actions', 'notActions'), ('dataActions', 'notDataActions'))


def _check_provider(tree):
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get('provider') != 'Azure':
            raise ValueError('emit_policy requires a tree whose nodes all have provider Azure')
        pending.extend(node.get('children', []))


def _raw(tree):
    raw = tree.get('condition_raw')
    if not raw:
        return {}
    try:
        document = json.loads(raw)
    except ValueError:
        return {}
    return document if isinstance(document, dict) else {}


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


def _block(node):
    condition = condition_version = None
    if node.get('name', '').startswith('Conditional permission block'):
        grant, condition_node = node.get('children', [])
        expression = condition_node.get('condition_json') or {}
        condition = expression.get('condition')
        condition_version = expression.get('conditionVersion')
        node = grant
    permission = {}
    for plane in node.get('children', []):
        include, exclude = plane.get('name', '').split(' minus ')
        parts = plane.get('children', [])
        if len(parts) != 2:
            raise ValueError(f'Unexpected Azure permission plane: {plane.get("name")!r}')
        permission[include] = _leaf_values(parts[0], include)
        not_node = parts[1]['children'][0] if parts[1].get('children') else parts[1]
        permission[exclude] = _leaf_values(not_node, exclude)
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


def _emit_rbac(tree, document):
    container = _container(document)
    original_blocks = container.get('permissions')
    if not isinstance(original_blocks, list):
        original_blocks = []
    blocks = []
    for index, node in enumerate(_blocks(tree)):
        built = _block(node)
        template = {}
        if index < len(original_blocks) and isinstance(original_blocks[index], dict):
            template = deepcopy(original_blocks[index])
        for key, value in built.items():
            if key in template or value:
                template[key] = value
        blocks.append(template)

    scopes = _scopes(tree)
    if 'Actions' in document:
        block = blocks[0] if blocks else {}
        for key, upper in zip(('actions', 'notActions', 'dataActions', 'notDataActions'),
                              ('Actions', 'NotActions', 'DataActions', 'NotDataActions')):
            if block.get(key) or upper in document:
                document[upper] = block.get(key, [])
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


def emit_policy(tree):
    """Return the Azure document reconstructed from an Azure policy tree."""
    validate_tree(tree)
    _check_provider(tree)
    document = _raw(tree)
    detail = tree.get('provider_detail')
    if detail == POLICY_DETAIL:
        return _emit_policy_definition(tree, document)
    if detail not in (RBAC_DETAIL, None):
        raise ValueError(f'Unsupported Azure provider_detail: {detail}')
    return _emit_rbac(tree, document)


emit_azure = emit_policy


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Rebuild an Azure role or policy definition from a policy tree')
    parser.add_argument('file', type=Path,
                        help='A policy tree JSON file, e.g. --dry-run output')
    parser.add_argument('--indent', type=int, default=2,
                        help='Indentation of the printed JSON (default: 2)')
    args = parser.parse_args(argv)
    try:
        tree = json.loads(args.file.read_text(encoding='utf-8-sig'))
        document = emit_policy(tree)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(document, indent=args.indent))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
