import contextlib
import io
import json
import unittest
from unittest.mock import MagicMock

from src import awsPolicyEntry, azurePolicyEntry, policyTree
from policy_support import ROOT, RecordingCursor


class PolicyTreeTests(unittest.TestCase):
    def test_schema_columns_and_parent_links(self):
        source = (ROOT / 'examples/aws-ec2-readonly.json').read_text()
        tree = awsPolicyEntry.parse_policy(source, name="O'Reilly")
        cursor = RecordingCursor()
        root_id = policyTree.insert_policy_tree(cursor, tree, schema='auth')
        self.assertEqual(root_id, 1)
        self.assertEqual(len(cursor.rows), 17)
        self.assertEqual(cursor.rows[0]['params'][1], "O'Reilly")
        self.assertIsNone(cursor.rows[0]['params'][0])
        self.assertIsNone(cursor.rows[0]['params'][-1])
        for offset in range(1, 17, 4):
            group = cursor.rows[offset]
            group_id = offset + 1
            self.assertEqual(group['params'][0], root_id)
            self.assertIsNone(group['params'][9])
            self.assertEqual(group['params'][-2:], [None, None])
            for row in cursor.rows[offset + 1:offset + 4]:
                self.assertEqual(row['params'][0], group_id)
                self.assertEqual(row['params'][4:7], ['AWS', 'arn:aws', 'AND'])
                self.assertIsInstance(row['params'][9], dict)
                self.assertEqual(len(row['params'][9]), 1)
                self.assertIn('"auth"."policy"', row['query'])
                self.assertIn('"operator_onChildren"', row['query'])
                self.assertNotIn("O'Reilly", row['query'])
        self.assertEqual(json.loads(tree['condition_raw']), json.loads(source))

    def test_azure_uses_the_same_writer(self):
        tree = azurePolicyEntry.parse_policy({'Actions': ['read'], 'Name': 'Reader'})
        cursor = RecordingCursor()
        self.assertEqual(policyTree.insert_policy_tree(cursor, tree), 1)
        self.assertTrue(all(row['params'][4] == 'Azure' for row in cursor.rows))

    def test_validation_occurs_before_any_insert(self):
        node = policyTree.make_node('root', 'AWS', 'arn:aws', children=[{'operator_onChildren': 'INVALID'}])
        cursor = RecordingCursor()
        with self.assertRaises(ValueError):
            policyTree.insert_policy_tree(cursor, node)
        self.assertFalse(cursor.rows)

    def test_cycles_shared_nodes_invalid_not_and_legacy_fields_are_rejected(self):
        root = policyTree.make_node('root', 'AWS', 'arn:aws')
        root['children'] = [root]
        child = policyTree.make_node('child', 'AWS', 'arn:aws')
        shared = policyTree.make_node('root', 'AWS', 'arn:aws', children=[child, child])
        invalid_not = policyTree.make_node('not', 'AWS', 'arn:aws', 'NOT')
        invalid_json = policyTree.make_node('bad', 'AWS', 'arn:aws', condition_json={'x': float('nan')})
        invalid_effect = policyTree.make_node('bad', 'AWS', 'arn:aws', effect=42)
        for tree in [root, shared, invalid_not, invalid_json, invalid_effect,
                     {'cloud': 'AWS', 'operator_onChildren': 'AND'}]:
            with self.assertRaises(ValueError):
                policyTree.validate_tree(tree)

    def test_sql_identifiers_are_quoted(self):
        cursor = RecordingCursor()
        policyTree.insert_policy_tree(cursor, policyTree.make_node('x', 'AWS', 'arn:aws'),
                                      table='x"; DROP TABLE policy; --')
        self.assertIn('"x""; DROP TABLE policy; --"', cursor.rows[0]['query'])

    def test_source_agreement_is_checked_only_when_requested(self):
        leaf = policyTree.make_node('leaf', 'AWS', 'arn:aws',
                                    condition_json={'x': 1}, condition_raw='{"x": 1}')
        tree = policyTree.make_node('root', 'AWS', 'arn:aws', 'OR', children=[leaf])
        policyTree.validate_tree(tree)
        leaf['condition_json'] = {'x': 2}
        with self.assertRaisesRegex(ValueError, 'describe different conditions'):
            policyTree.validate_tree(tree)
        policyTree.validate_tree(tree, check_source=False)

    def test_validation_errors_name_the_node_path(self):
        leaf = policyTree.make_node('leaf', 'AWS', 'arn:aws')
        leaf['unknown'] = 'x'
        tree = policyTree.make_node('root', 'AWS', 'arn:aws', children=[leaf])
        with self.assertRaisesRegex(ValueError, r'root/children\[0\].*Unknown policy fields'):
            policyTree.validate_tree(tree)

    def test_subtract_is_rejected(self):
        tree = policyTree.make_node('root', 'AWS', 'arn:aws', 'SUBTRACT')
        with self.assertRaisesRegex(ValueError, 'Policy operator'):
            policyTree.validate_tree(tree)

    def test_transaction_success_failure_and_autocommit(self):
        connection = MagicMock()
        connection.autocommit = False
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (42,)
        tree = policyTree.make_node('root', 'AWS', 'arn:aws', children=[
            policyTree.make_node('child', 'AWS', 'arn:aws')])
        self.assertEqual(policyTree.write_policy_tree(connection, tree), 42)
        connection.__exit__.assert_called_once_with(None, None, None)
        connection.reset_mock()
        cursor.execute.side_effect = [None, RuntimeError('child failed')]
        with self.assertRaises(RuntimeError):
            policyTree.write_policy_tree(connection, tree)
        self.assertIs(connection.__exit__.call_args.args[0], RuntimeError)
        connection.autocommit = True
        with self.assertRaises(ValueError):
            policyTree.write_policy_tree(connection, tree)

    def test_strict_json_loading(self):
        for source in ['{"x": 1, "x": 2}', '{"x": NaN}', '[]', {'x': float('inf')}]:
            with self.assertRaises(ValueError):
                policyTree.load_document(source)

    def test_both_cli_dry_runs(self):
        for module, filename in [(awsPolicyEntry, 'aws-ec2-readonly.json'),
                                 (azurePolicyEntry, 'azure-classic-vm-role.json')]:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(module.main([str(ROOT / 'examples' / filename), '--dry-run']), 0)
            policyTree.validate_tree(json.loads(output.getvalue()))

    def test_dry_run_can_skip_cel_enrichment(self):
        sample = str(ROOT / 'examples' / 'aws-ec2-readonly.json')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(awsPolicyEntry.main([sample, '--dry-run', '--no-cel']), 0)
        tree = json.loads(output.getvalue())
        leaf = tree['children'][0]['children'][1]
        self.assertEqual(leaf['condition_json'], {'Action': 'ec2:Describe*'})
        self.assertEqual(leaf['condition_raw_type'], 'json')
        self.assertIsNone(leaf['condition_cel'])
