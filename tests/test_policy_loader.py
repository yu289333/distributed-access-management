import json
import unittest
from unittest.mock import patch

from src.awsPolicyEmitter import emit_policy
from src.awsPolicyEntry import parse_policy
from src.policyTree import COLUMNS, load_policy_tree
from policy_support import ROOT


class RowsCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def execute(self, query, params=None):
        self.executed.append((query, params))

    def fetchall(self):
        return self.rows


def row(node_id, parent, operator='AND', condition_json=None):
    values = {column: None for column in COLUMNS}
    values.update(operator=operator, condition_json=condition_json)
    return (node_id, parent, *(values[column] for column in COLUMNS))


def flatten(tree, start=1):
    rows = []
    counter = start

    def visit(node, parent):
        nonlocal counter
        node_id = counter
        counter += 1
        rows.append((node_id, parent, *(node.get(column) for column in COLUMNS)))
        for child in node['children']:
            visit(child, node_id)

    visit(tree, None)
    return rows


def rendered(query):
    with patch('psycopg2.extensions.quote_ident',
               side_effect=lambda value, context: value):
        return query.as_string(None)


class LoadPolicyTreeTests(unittest.TestCase):
    def test_a_stored_tree_is_rebuilt_and_can_be_emitted(self):
        source = (ROOT / 'examples/aws-ec2-readonly.json').read_text()
        tree = parse_policy(source)
        cursor = RowsCursor(flatten(tree))
        loaded = load_policy_tree(cursor, 1)
        self.assertEqual(loaded, tree)
        self.assertEqual(emit_policy(loaded), json.loads(source))

    def test_the_query_is_recursive_and_quotes_identifiers(self):
        cursor = RowsCursor([row(1, None)])
        load_policy_tree(cursor, 1, table='policy', schema='iam')
        query, params = cursor.executed[0]
        self.assertEqual(params, (1,))
        self.assertIn('WITH RECURSIVE', rendered(query))
        self.assertIn('iam.policy', rendered(query))

    def test_a_missing_root_is_rejected(self):
        with self.assertRaises(ValueError):
            load_policy_tree(RowsCursor([]), 7)

    def test_a_parent_cycle_is_rejected(self):
        rows = [row(1, None), row(2, 1), row(3, 2), row(4, 3)]
        rows.append((2, 4, *(row(9, None)[2:])))
        with self.assertRaisesRegex(ValueError, 'cycle'):
            load_policy_tree(RowsCursor(rows), 1)

    def test_invalid_rows_are_rejected_by_validation(self):
        with self.assertRaises(ValueError):
            load_policy_tree(RowsCursor([row(1, None, operator='MAYBE')]), 1)


if __name__ == '__main__':
    unittest.main()
