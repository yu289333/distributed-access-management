from copy import deepcopy
import json
import unittest

from src.providers.azure.entry import parse_policy
from src.tree import validate_tree
from policy_support import ROOT, documents, walk


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

    def test_unknown_permission_fields_become_leaves(self):
        source = {'permissions': [{'actions': ['read'],
                                   'futureField': {'nested': [1, 2]}}]}
        tree = parse_policy(source)
        grant = tree['children'][0]
        leaf = next(child for child in grant['children']
                    if child['name'] == 'futureField')
        self.assertEqual(leaf['condition_json'],
                         {'futureField': {'nested': [1, 2]}})

    def test_powershell_example_uses_the_single_block_shape(self):
        tree = parse_policy((ROOT / 'examples/azure-powershell-web-app.json').read_text())
        self.assertEqual(tree['display_name'], 'Web App Contributor')
        self.assertEqual(tree['provider_detail'],
                         'Microsoft.Authorization/roleDefinitions')
        self.assertTrue(any('Microsoft.Web/sites/*' in (leaf['condition_json'] or {}).get('actions', [])
                            for leaf in walk(tree)))

    def test_permission_arrays_are_direct_leaves(self):
        permission = {'actions': ['read', 'write'], 'notActions': ['write'],
                      'dataActions': ['read', 'delete'], 'notDataActions': ['delete']}
        tree = parse_policy({'permissions': [permission]})
        block = tree['children'][0]
        self.assertEqual(block['operator_onChildren'], 'AND')
        self.assertEqual([leaf['condition_json'] for leaf in block['children']],
                         [{key: value} for key, value in permission.items()])
        self.assertTrue(all(not leaf['children'] and leaf['child_position'] is None
                            for leaf in block['children']))

    def test_not_actions_stays_in_its_permission_block(self):
        tree = parse_policy({'permissions': [
            {'actions': ['read', 'write'], 'notActions': ['write']},
            {'actions': ['write']}]})
        self.assertEqual([[leaf['condition_json'] for leaf in block['children']]
                          for block in tree['children']],
                         [[{'actions': ['read', 'write']}, {'notActions': ['write']}],
                          [{'actions': ['write']}]])

    def test_explicitly_empty_permission_arrays_are_preserved(self):
        tree = parse_policy({'permissions': [{'actions': [], 'dataActions': []}]})
        self.assertEqual([leaf['condition_json'] for leaf in tree['children'][0]['children']],
                         [{'actions': []}, {'dataActions': []}])

    def test_policy_assignment_keeps_scopes_as_direct_condition_leaves(self):
        properties = {'scope': '/subscriptions/example', 'notScopes': ['/subscriptions/example/resourceGroups/dev'],
                      'policyDefinitionId': '/providers/Microsoft.Authorization/policyDefinitions/example'}
        tree = parse_policy(json.dumps({'type': 'Microsoft.Authorization/policyAssignments',
                                        'properties': properties}))
        self.assertEqual(tree['operator_onChildren'], 'AND')
        self.assertEqual([child['name'] for child in tree['children']], ['scope', 'notScopes'])
        for child in tree['children']:
            self.assertIsNone(child['child_position'])
            self.assertEqual(child['children'], [])
            key = child['name']
            self.assertEqual(child['condition_json'], {key: properties[key]})

    def test_deny_assignment_keeps_principal_fields_as_direct_children(self):
        properties = {'principals': [{'id': 'principal', 'type': 'Group'}],
                      'excludePrincipals': [{'id': 'exception', 'type': 'User'}],
                      'permissions': [{'actions': ['write'], 'notActions': ['read']}]}
        tree = parse_policy({'type': 'Microsoft.Authorization/denyAssignments', 'properties': properties})
        self.assertEqual(tree['operator_onChildren'], 'AND')
        self.assertEqual([child['name'] for child in tree['children']],
                         ['permissions', 'principals', 'excludePrincipals'])
        permissions, principals, excluded = tree['children']
        for child in (principals, excluded):
            self.assertIsNone(child['child_position'])
            self.assertEqual(child['children'], [])
            key = child['name']
            self.assertEqual(child['condition_json'], {key: properties[key]})
        self.assertEqual([leaf['condition_json'] for leaf in permissions['children'][0]['children']],
                         [{'actions': ['write']}, {'notActions': ['read']}])

    def test_negated_rule_comparisons_stay_as_source_leaves(self):
        comparisons = [{'field': 'location', 'notIn': ['eastus']},
                       {'field': 'name', 'notLike': 'example*'},
                       {'value': "[field('name')]", 'notContains': 'foo'}]
        tree = parse_policy(json.dumps({'policyRule': {'if': {'allOf': comparisons},
                                                      'then': {'effect': 'audit'}}}))
        applicability = tree['children'][0]
        self.assertEqual(applicability['operator_onChildren'], 'AND')
        for condition, expression in zip(applicability['children'], comparisons):
            self.assertEqual(condition['condition_json'], expression)
            self.assertEqual(condition['children'], [])
            self.assertIsNone(condition['condition_cel'])

    def test_rest_cli_and_powershell_shapes(self):
        for source in [
            {'id': 'role-id', 'properties': {'roleName': 'Reader', 'permissions': [{'actions': ['read']}]}},
            {'roleName': 'Reader', 'permissions': [{'actions': ['read']}], 'assignableScopes': ['/']},
            {'Name': 'Reader', 'Actions': ['read'], 'NotActions': [], 'DataActions': [], 'NotDataActions': []}]:
            tree = parse_policy(source, name='override')
            self.assertEqual(tree['name'], 'override')
            self.assertEqual(tree['display_name'], 'Reader')
            self.assertTrue(any(node['condition_json'] == {'actions': ['read']} for node in walk(tree)))

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
        self.assertEqual([node['operator_onChildren'] for node in walk(tree)].count('NOT'), 1)
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
        self.assertEqual(applicability['operator_onChildren'], 'AND')
        self.assertEqual(applicability['children'][1]['operator_onChildren'], 'NOT')
        self.assertEqual(outcome['operator_onChildren'], 'AND')
        effect, details = outcome['children']
        self.assertEqual(effect['condition_cel'], 'effect == "audit"')
        self.assertEqual(effect['condition_json'], {'effect': 'audit'})
        self.assertEqual(effect['condition_raw'], '"effect": "audit"')
        self.assertEqual(details['name'], 'details')
        self.assertEqual(details['operator_onChildren'], 'AND')
        self.assertEqual(details['children'][0]['condition_cel'], 'type == "Microsoft.Compute/virtualMachines"')
        self.assertEqual(details['children'][-1]['condition_cel'], 'severity == "Critical"')
        self.assertEqual([n['condition_json'] for n in details['children']],
                         [{k: v} for k, v in document['policyRule']['then']['details'].items()])

    def test_classic_role_has_scope_expression(self):
        source = (ROOT / 'examples/azure-classic-vm-role.json').read_text()
        tree = parse_policy(source)
        self.assertEqual(tree['operator_onChildren'], 'AND')
        permissions, scopes = tree['children']
        self.assertEqual(permissions['operator_onChildren'], 'OR')
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
