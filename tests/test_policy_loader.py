import json
import unittest

from src.awsPolicyEmitter import emit_policy
from src.awsPolicyEntry import parse_policy
from src.policyTree import COLUMNS, load_policy_tree
from policy_support import ROOT


class RowsCursor:
    """Minimal cursor for export_policy_tree: one execute, one fetchall."""

    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute(self, query, params=None):
        self.connection.executed.append((query, params))

    def fetchall(self):
        return self.connection.rows


class RowsConnection:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def cursor(self):
        return RowsCursor(self)


def flatten(tree, start=1):
    rows, counter = [], [start]

    def visit(node, parent):
        node_id = counter[0]
        counter[0] += 1
        rows.append((node_id, parent, *(node.get(column) for column in COLUMNS)))
        for child in node['children']:
            visit(child, node_id)

    visit(tree, None)
    return rows


class LoadPolicyTreeTests(unittest.TestCase):
    def test_a_stored_tree_is_rebuilt_and_can_be_emitted(self):
        source = (ROOT / 'examples/aws-ec2-readonly.json').read_text()
        tree = parse_policy(source)
        connection = RowsConnection(flatten(tree))
        loaded = load_policy_tree(connection, 1)
        self.assertEqual(loaded, tree)
        self.assertEqual(emit_policy(loaded), json.loads(source))
        self.assertIn('WITH RECURSIVE', connection.executed[0][0])
        self.assertEqual(connection.executed[0][1], (1,))

    def test_a_missing_root_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'not found'):
            load_policy_tree(RowsConnection([]), 7)

    def test_invalid_rows_are_rejected_by_validation(self):
        values = {column: None for column in COLUMNS}
        values['operator'] = 'MAYBE'
        rows = [(1, None, *(values[column] for column in COLUMNS))]
        with self.assertRaises(ValueError):
            load_policy_tree(RowsConnection(rows), 1)


if __name__ == '__main__':
    unittest.main()
