import json
import unittest

from src.awsPolicyEntry import parse_policy
from src.azurePolicyEntry import parse_policy as azure
from src.conditionExpression import condition_to_cel
from src.conditions.source import decode_json_condition, register_condition_format
from src.policyTree import validate_tree


class ConditionSourceTests(unittest.TestCase):
    def test_exact_json_input_fragments_and_equal_representations(self):
        raw = '{"Statement": [{ "Effect" : "Allow", "Action" : [ "read", "write" ], "Resource": "\\u002a" }]}'
        tree = parse_policy(raw)
        self.assertEqual(tree['condition_raw'], raw)
        leaves = tree['children'][0]['children']
        self.assertEqual(leaves[1]['condition_raw'], '"Action" : [ "read", "write" ]')
        self.assertEqual(leaves[2]['condition_raw'], '"Resource": "\\u002a"')
        for node in leaves:
            self.assertEqual(node['condition_raw_type'], 'json')
            self.assertEqual(decode_json_condition(node['condition_raw']), node['condition_json'])
            self.assertEqual(condition_to_cel(node['condition_json'], node['condition_raw'],
                                             provider='AWS', condition_raw_type='json'), node['condition_cel'])
        leaves[0]['condition_json'] = {'Effect': 'Deny'}
        with self.assertRaisesRegex(ValueError, 'different conditions'):
            validate_tree(tree)

    def test_raw_only_conversion_and_unknown_format(self):
        self.assertEqual(condition_to_cel(condition_raw='"Action" : [ "read" ]',
                                         provider='AWS', condition_raw_type='json'), 'Action == ["read"]')
        with self.assertRaisesRegex(ValueError, 'Unsupported condition_raw_type'):
            condition_to_cel(condition_raw='Action: read', provider='AWS', condition_raw_type='yaml')
        raw = 'user.age >= 18'
        self.assertEqual(condition_to_cel(condition_raw=raw, provider='AWS', condition_raw_type='cel'), raw)

    def test_future_format_adapter_does_not_rewrite_raw(self):
        register_condition_format('test-key-value', lambda raw: dict([raw.split('=', 1)]))
        raw = 'Action=read'
        self.assertEqual(condition_to_cel(condition_raw=raw, provider='AWS',
                                         condition_raw_type='test-key-value'), 'Action == "read"')
        with self.assertRaisesRegex(ValueError, 'different conditions'):
            condition_to_cel({'Action': 'write'}, raw, provider='AWS', condition_raw_type='test-key-value')

    def test_object_input_has_no_invented_raw_leaf(self):
        tree = parse_policy({'Statement': {'Effect': 'Allow', 'Action': 'read', 'Resource': '*'}})
        self.assertIsNone(tree['children'][0]['children'][0]['condition_raw'])

    def test_azure_array_keeps_one_original_field(self):
        raw = '{"permissions":[{"actions" : [ "read", "write" ]}]}'
        tree = azure(raw)
        def visit(node):
            if node['condition_json'] is not None:
                self.assertEqual(node['condition_raw'], '{"actions" : [ "read", "write" ]}')
                self.assertEqual(node['condition_json'], {'actions': ['read', 'write']})
            for child in node['children']:
                visit(child)
        visit(tree)
