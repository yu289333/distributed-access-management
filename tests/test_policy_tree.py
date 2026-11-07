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
        self.assertEqual(len(cursor.rows), 5)
        self.assertEqual(cursor.rows[0]['params'][1], "O'Reilly")
        self.assertIsNone(cursor.rows[0]['params'][0])
        for row in cursor.rows[1:]:
            self.assertEqual(row['params'][0], root_id)
            self.assertEqual(row['params'][4:7], ['AWS', 'arn:aws', 'AND'])
            self.assertIsInstance(row['params'][9], dict)
            self.assertIn('"auth"."policy"', row['query'])
            self.assertNotIn("O'Reilly", row['query'])
        self.assertEqual(json.loads(tree['condition_raw']), json.loads(source))

    def test_azure_uses_the_same_writer(self):
        tree = azurePolicyEntry.parse_policy({'Actions': ['read'], 'Name': 'Reader'})
        cursor = RecordingCursor()
        self.assertEqual(policyTree.insert_policy_tree(cursor, tree), 1)
        self.assertTrue(all(row['params'][4] == 'Azure' for row in cursor.rows))

    def test_validation_occurs_before_any_insert(self):
        node = policyTree.make_node('root', 'AWS', 'arn:aws', children=[{'operator': 'INVALID'}])
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
        for tree in [root, shared, invalid_not, invalid_json, {'cloud': 'AWS', 'operator': 'AND'}]:
            with self.assertRaises(ValueError):
                policyTree.validate_tree(tree)

    def test_sql_identifiers_are_quoted(self):
        cursor = RecordingCursor()
        policyTree.insert_policy_tree(cursor, policyTree.make_node('x', 'AWS', 'arn:aws'),
                                      table='x"; DROP TABLE policy; --')
        self.assertIn('"x""; DROP TABLE policy; --"', cursor.rows[0]['query'])

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
