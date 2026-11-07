from copy import deepcopy
import json
import unittest

from src.azurePolicyEntry import parse_policy
from src.policyTree import validate_tree
from policy_support import ROOT, documents, evaluate, walk


def action_matches(plane, action):
    def match(expression):
        # Exact matching only: these tests verify set structure, not Azure wildcards.
        return action in expression.get(plane, []) or action in expression.get(
            'notActions' if plane == 'actions' else 'notDataActions', [])
    return match


class AzureParserTests(unittest.TestCase):
    def test_repository_roles_and_policy_rule(self):
        examples = list(documents('db/azurePolicies.txt'))
        examples.extend(json.loads(path.read_text()) for path in (ROOT / 'examples').glob('azure-*.json'))
        supported = 0
        for source in examples:
            if source.get('type') == 'Microsoft.Authorization/locks' or 'resources' in source:
                with self.assertRaises(ValueError):
                    parse_policy(source)
                continue
            original = deepcopy(source)
            tree = parse_policy(source)
            validate_tree(tree)
            self.assertEqual(json.loads(tree['condition_raw']), source)
            self.assertEqual(source, original)
            self.assertEqual(tree['provider'], 'Azure')
            supported += 1
        self.assertGreaterEqual(supported, 9)

    def test_control_and_data_planes_are_separate(self):
        tree = parse_policy({'permissions': [{
            'actions': ['read', 'write'], 'notActions': ['write'],
            'dataActions': ['read', 'delete'], 'notDataActions': ['delete']}]})
        for plane, action, expected in [('actions', 'read', True), ('actions', 'write', False),
                                        ('dataActions', 'read', True), ('dataActions', 'delete', False),
                                        ('dataActions', 'write', False)]:
            self.assertEqual(evaluate(tree, action_matches(plane, action)), expected)

    def test_not_actions_is_not_a_global_deny(self):
        tree = parse_policy({'permissions': [
            {'actions': ['read', 'write'], 'notActions': ['write']},
            {'actions': ['write']}]})
        self.assertTrue(evaluate(tree, action_matches('actions', 'write')))

    def test_empty_role_grants_nothing(self):
        tree = parse_policy({'permissions': [{'actions': [], 'dataActions': []}]})
        self.assertFalse(evaluate(tree, lambda expression: True))

    def test_rest_cli_and_powershell_shapes(self):
        for source in [
            {'id': 'role-id', 'properties': {'roleName': 'Reader', 'permissions': [{'actions': ['read']}]}},
            {'roleName': 'Reader', 'permissions': [{'actions': ['read']}], 'assignableScopes': ['/']},
            {'Name': 'Reader', 'Actions': ['read'], 'NotActions': [], 'DataActions': [], 'NotDataActions': []}]:
            tree = parse_policy(source, name='override')
            self.assertEqual(tree['name'], 'override')
            self.assertEqual(tree['display_name'], 'Reader')
            self.assertTrue(evaluate(tree, action_matches('actions', 'read')))

    def test_conditional_permissions_are_not_dropped(self):
        tree = parse_policy({'permissions': [{'actions': ['read'], 'condition': 'request == allowed',
                                              'conditionVersion': '2.0'}]})
        expressions = [node['condition_json'] for node in walk(tree) if node['condition_json']]
        self.assertIn({'condition': 'request == allowed', 'conditionVersion': '2.0'}, expressions)

    def test_governance_logical_operators_and_effect_are_preserved(self):
        source = {'properties': {'displayName': 'Audit VM', 'policyRule': {
            'if': {'allOf': [{'field': 'type', 'equals': 'VM'},
                             {'anyOf': [{'field': 'location', 'equals': 'east'},
                                        {'not': {'field': 'encrypted', 'equals': True}}]}]},
            'then': {'effect': 'audit', 'details': {'message': 'check encryption'}}},
            'parameters': {'location': {'type': 'String'}}}}
        tree = parse_policy(source)
        self.assertEqual(tree['provider_detail'], 'Microsoft.Authorization/policyDefinitions')
        self.assertIn('audit', tree['comment'])
        self.assertEqual(json.loads(tree['condition_raw']), source)
        self.assertEqual([node['operator'] for node in walk(tree)].count('NOT'), 1)
        self.assertIsNone(tree['condition_json'])

    def test_malformed_and_unsupported_policies_are_rejected(self):
        for source in [{}, {'permissions': []}, {'permissions': [{}]},
                       {'permissions': [{'actions': 'read'}]},
                       {'policyRule': {'if': {'allOf': []}, 'then': {'effect': 'audit'}}},
                       {'policyRule': {'if': {'not': {}}, 'then': {'effect': 'audit'}}},
                       {'policyRule': {'if': {'allOf': [{}], 'field': 'x'}, 'then': {'effect': 'deny'}}},
                       {'policyRule': {'if': {'field': 'type'}, 'then': {}}}]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_policy(source)
