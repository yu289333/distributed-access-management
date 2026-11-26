from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from src.awsPolicyEntry import parse_policy as parse_aws
from src.azurePolicyEntry import parse_policy
from src.azurePolicyEmitter import emit_azure, emit_policy, main
from src.policyTree import strip_database_ids
from policy_support import ROOT

GENERATED = (
    ('azure-audit-vm-db-tree.json', 'azure-audit-vm.json'),
    ('azure-classic-vm-role-db-tree.json', 'azure-classic-vm-role.json'),
    ('azure-spring-role-db-tree.json', 'azure-spring-role.json'),
)


class AzureEmitterTests(unittest.TestCase):
    def test_examples_round_trip_exactly(self):
        for path in sorted((ROOT / 'examples').glob('azure-*.json')):
            with self.subTest(path=path.name):
                source = json.loads(path.read_text())
                self.assertEqual(emit_policy(parse_policy(path.read_text())), source)

    def test_generated_exports_round_trip_to_their_sources(self):
        for generated, source in GENERATED:
            with self.subTest(generated=generated):
                tree = strip_database_ids(json.loads(
                    (ROOT / 'examples/generated' / generated).read_text()))
                expected = json.loads((ROOT / 'examples' / source).read_text())
                self.assertEqual(emit_policy(tree), expected)

    def test_rbac_edits_are_reflected(self):
        tree = parse_policy((ROOT / 'examples/azure-classic-vm-role.json').read_text())
        leaf = tree['children'][0]['children'][0]['children'][0]
        leaf['condition_json']['actions'] = ['Microsoft.Foo/read']
        leaf['condition_raw'] = None
        document = emit_policy(tree)
        self.assertEqual(document['permissions'][0]['actions'][0], 'Microsoft.Foo/read')

    def test_rbac_emits_direct_permission_leaves_without_source(self):
        source = {'permissions': [{'actions': ['read'], 'notActions': [],
                                   'dataActions': ['view'], 'notDataActions': ['delete']}]}
        tree = parse_policy(source)
        tree['condition_raw'] = None
        tree['children'][0]['children'].reverse()
        self.assertEqual(emit_policy(tree), source)

    def test_policy_assignment_round_trip_reads_edited_exclusions(self):
        source = {'type': 'Microsoft.Authorization/policyAssignments', 'scope': '/subscriptions/example',
                  'properties': {'policyDefinitionId': '/example/policy', 'notScopes': ['/example/old']}}
        tree = parse_policy(source)
        self.assertEqual(emit_policy(tree), source)
        excluded = tree['children'][1]
        excluded['condition_json']['notScopes'] = ['/example/new']
        tree['children'].reverse()
        self.assertEqual(emit_policy(tree)['properties']['notScopes'], ['/example/new'])

    def test_deny_assignment_round_trip_reads_edited_exclusions(self):
        source = {'type': 'Microsoft.Authorization/denyAssignments', 'properties': {
            'principals': [{'id': 'principal', 'type': 'Group'}],
            'excludePrincipals': [{'id': 'old', 'type': 'User'}],
            'scope': '/subscriptions/example',
            'permissions': [{'actions': ['write'], 'notActions': ['read']}]}}
        tree = parse_policy(source)
        self.assertEqual(emit_policy(tree), source)
        excluded = tree['children'][2]
        excluded['condition_json']['excludePrincipals'][0]['id'] = 'new'
        tree['children'].reverse()
        self.assertEqual(emit_policy(tree)['properties']['excludePrincipals'], [{'id': 'new', 'type': 'User'}])

    def test_policy_definition_edits_are_reflected(self):
        tree = parse_policy((ROOT / 'examples/azure-audit-vm.json').read_text())
        effect = tree['children'][1]['children'][0]
        effect['condition_json']['effect'] = 'deny'
        effect['condition_raw'] = None
        document = emit_policy(tree)
        self.assertEqual(document['policyRule']['then']['effect'], 'deny')

    def test_non_azure_trees_are_rejected(self):
        with self.assertRaises(ValueError):
            emit_policy(parse_aws({'Statement': {'Effect': 'Allow', 'Action': '*',
                                                 'Resource': '*'}}))

    def test_emit_azure_is_an_alias(self):
        source = (ROOT / 'examples/azure-spring-role.json').read_text()
        self.assertEqual(emit_azure(parse_policy(source)), emit_policy(parse_policy(source)))

    def test_cli_reads_a_dry_run_tree(self):
        source = json.loads((ROOT / 'examples/azure-audit-vm.json').read_text())
        tree_text = json.dumps(parse_policy(json.dumps(source)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tree.json'
            path.write_text(tree_text)
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(path)]), 0)
        self.assertEqual(json.loads(output.getvalue()), source)


if __name__ == '__main__':
    unittest.main()
