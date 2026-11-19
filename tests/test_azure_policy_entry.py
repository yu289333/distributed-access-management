from copy import deepcopy
import json
import unittest

from src.azurePolicyEntry import parse_policy
from src.policyTree import validate_tree
from policy_support import ROOT, documents, evaluate, walk


def action_matches(plane, action):
    def match(expression):
        if 'assignableScopes' in expression:
            return True  # Scope eligibility is metadata, independent of action matching.
        # Exact matching only: these tests verify set structure, not Azure wildcards.
        return action in expression.get(plane, []) or action in expression.get(
            'notActions' if plane == 'actions' else 'notDataActions', [])
    return match


class AzureParserTests(unittest.TestCase):
    def test_repository_roles_and_policy_rule(self):
        examples = list(documents('db/azurePolicies.txt'))
        examples.extend(json.loads(path.read_text()) for path in (ROOT / 'examples').glob('azure-*.json') if not path.name.endswith('-sql.json'))
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
        self.assertIn({'effect': 'audit'}, [n['condition_json'] for n in walk(tree)])
        self.assertEqual(json.loads(tree['condition_raw']), source)
        self.assertEqual([node['operator'] for node in walk(tree)].count('NOT'), 1)
        self.assertIsNone(tree['condition_json'])

    def test_audit_example_matches_sql_sketch_with_predicate_cel(self):
        raw = (ROOT / 'examples/azure-audit-vm.json').read_text()
        document = json.loads(raw)
        tree = parse_policy(raw)
        self.assertEqual(tree['name'], '"mode": "Indexed" "policyRule"')
        self.assertEqual(tree['display_name'], document['displayName'])
        self.assertEqual(tree['comment'], '"description": ' + json.dumps(document['description']))
        self.assertEqual(tree['condition_raw'], raw)
        self.assertEqual(len(list(walk(tree))), 12)
        predicates = [n for n in walk(tree) if n['condition_json'] and 'field' in n['condition_json']]
        self.assertEqual(len(predicates), 2)
        self.assertTrue(all(n['condition_cel'] is not None for n in predicates))
        self.assertTrue(all(n['condition_cel'] is not None for n in walk(tree) if n['condition_json'] is not None))
        self.assertTrue(all(n['condition_cel'] is None for n in walk(tree) if n['children']))
        applicability, outcome = tree['children']
        self.assertEqual(applicability['operator'], 'AND')
        self.assertEqual(applicability['children'][1]['operator'], 'NOT')
        self.assertEqual(outcome['operator'], 'AND')
        effect, details = outcome['children']
        self.assertEqual(effect['condition_cel'], 'effect == "audit"')
        self.assertEqual(effect['condition_json'], {'effect': 'audit'})
        self.assertEqual(effect['condition_raw'], '"effect": "audit"')
        self.assertEqual(details['name'], 'details')
        self.assertEqual(details['operator'], 'AND')
        self.assertEqual(details['children'][0]['condition_cel'], 'type == "Microsoft.Compute/virtualMachines"')
        self.assertEqual(details['children'][-1]['condition_cel'], 'severity == "Critical"')
        self.assertEqual([n['condition_json'] for n in details['children']],
                         [{k: v} for k, v in document['policyRule']['then']['details'].items()])

    def test_classic_role_has_scope_expression(self):
        source = (ROOT / 'examples/azure-classic-vm-role.json').read_text()
        tree = parse_policy(source)
        self.assertEqual(tree['operator'], 'AND')
        permissions, scopes = tree['children']
        self.assertEqual(permissions['operator'], 'OR')
        self.assertEqual(scopes['name'], 'assignableScopes')
        self.assertEqual(scopes['condition_json'], {'assignableScopes': ['/']})
        self.assertEqual(scopes['condition_cel'], 'assignableScopes == ["/"]')
        source = json.loads(source)
        source['assignableScopes'] = ['/', '/abc']
        scopes = parse_policy(source)['children'][1]
        self.assertEqual(scopes['children'], [])
        self.assertEqual(scopes['condition_json'], {'assignableScopes': ['/', '/abc']})
        self.assertEqual(scopes['condition_cel'], 'assignableScopes == ["/", "/abc"]')
        source['assignableScopes'] = []
        self.assertEqual(parse_policy(source)['children'][1]['condition_cel'], 'assignableScopes == []')
        source['assignableScopes'] = '/'
        with self.assertRaises(ValueError):
            parse_policy(source)

    def test_malformed_and_unsupported_policies_are_rejected(self):
        for source in [{}, {'permissions': []}, {'permissions': [{}]},
                       {'permissions': [{'actions': 'read'}]},
                       {'policyRule': {'if': {'allOf': []}, 'then': {'effect': 'audit'}}},
                       {'policyRule': {'if': {'not': {}}, 'then': {'effect': 'audit'}}},
                       {'policyRule': {'if': {'allOf': [{}], 'field': 'x'}, 'then': {'effect': 'deny'}}},
                       {'policyRule': {'if': {'field': 'type'}, 'then': {}}}]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_policy(source)
