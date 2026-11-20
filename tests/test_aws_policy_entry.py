from copy import deepcopy
import json
import unittest

from src.awsPolicyEntry import parse_policy
from src.policyTree import validate_tree
from policy_support import ROOT, documents, evaluate, walk


class AwsParserTests(unittest.TestCase):
    def test_repository_examples_are_lossless(self):
        examples = list(documents('db/awsPolicies.txt'))
        examples.extend(json.loads(path.read_text()) for path in (ROOT / 'examples').glob('aws-*.json') if not path.name.endswith('-sql.json'))
        self.assertGreaterEqual(len(examples), 7)
        for source in examples:
            with self.subTest(source=source):
                original = deepcopy(source)
                tree = parse_policy(source, name='example')
                validate_tree(tree)
                statements = [json.loads(node['condition_raw']) for node in walk(tree)
                              if node['children'] and node['condition_raw']
                              and 'Effect' in json.loads(node['condition_raw'])]
                expected = source.get('Document', source)['Statement']
                self.assertCountEqual(statements, expected if isinstance(expected, list) else [expected])
                self.assertEqual(json.loads(tree['condition_raw']), source)
                self.assertEqual(source, original)
                self.assertTrue(all(node['provider'] == 'AWS' for node in walk(tree)))

    def test_example_cel_matches_each_json_field(self):
        for filename in ('aws-ec2-readonly.json', 'aws-secrets-readonly.json'):
            tree = parse_policy((ROOT / 'examples' / filename).read_text())
            for node in walk(tree):
                expression = node['condition_json']
                if expression is not None:
                    self.assertEqual(len(expression), 1)
                    key, value = next(iter(expression.items()))
                    self.assertEqual(node['condition_cel'], key + ' == ' + json.dumps(value))
                elif node['children']:
                    self.assertIsNone(node['condition_cel'])

    def test_additional_aws_documentation_structures(self):
        cases = {
            'aws-s3-deny-except-bucket.json': ('AND', 2),
            'aws-deny-outside-regions.json': ('AND', 1),
            'aws-deny-outside-ip-ranges.json': ('AND', 1),
            'aws-create-user-with-tags.json': ('OR', 1),
            'aws-ec2-trust-policy.json': ('OR', 1),
        }
        for filename, (operator, statement_count) in cases.items():
            with self.subTest(filename=filename):
                raw = (ROOT / 'examples' / filename).read_text()
                source = json.loads(raw)
                statements = source['Statement']
                statements = statements if isinstance(statements, list) else [statements]
                self.assertEqual(len(statements), statement_count)
                tree = parse_policy(raw)
                self.assertEqual(tree['operator'], operator)
                actual = [node['condition_json'] for node in walk(tree)
                          if node['condition_json'] is not None]
                expected = [{key: value} for statement in statements
                            for key, value in statement.items() if key != 'Sid']
                self.assertCountEqual(actual, expected)
                self.assertEqual(tree['condition_raw'], raw)
                for node in walk(tree):
                    if node['condition_json'] is not None:
                        key, value = next(iter(node['condition_json'].items()))
                        self.assertEqual(node['condition_cel'], key + ' == ' + json.dumps(value))
        trust = parse_policy((ROOT / 'examples/aws-ec2-trust-policy.json').read_text())
        self.assertFalse(any('Resource' in (n['condition_json'] or {}) for n in walk(trust)))
        tagged = parse_policy((ROOT / 'examples/aws-create-user-with-tags.json').read_text())
        condition = next(n['condition_json']['Condition'] for n in walk(tagged)
                         if n['condition_json'] and 'Condition' in n['condition_json'])
        self.assertIn('ForAllValues:StringEquals', condition)
        self.assertIn('StringEqualsIfExists', condition)

    def test_explicit_deny_overrides_allow(self):
        tree = parse_policy({'Statement': [
            {'Sid': 'allow', 'Effect': 'Allow', 'Action': '*', 'Resource': '*'},
            {'Sid': 'deny', 'Effect': 'Deny', 'NotAction': 'iam:*', 'Resource': '*',
             'Condition': {'BoolIfExists': {'aws:MultiFactorAuthPresent': 'false'}}}]})
        for matched, expected in [(set(), False), ({'allow'}, True),
                                  ({'deny'}, False), ({'allow', 'deny'}, False)]:
            self.assertEqual(evaluate(tree, lambda s: ('allow' in matched if 'Action' in s else
                                                      'deny' in matched if 'NotAction' in s else True)), expected)

    def test_deny_only_never_grants(self):
        tree = parse_policy({'Statement': {'Effect': 'Deny', 'Action': '*', 'Resource': '*'}})
        self.assertFalse(evaluate(tree, lambda s: True))
        self.assertFalse(evaluate(tree, lambda s: False))

    def test_trust_and_resource_policies(self):
        for statement in [
            {'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': {'Service': 'lambda.amazonaws.com'}},
            {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::example/*', 'Principal': '*'},
            {'Effect': 'Deny', 'NotAction': 's3:GetObject', 'NotResource': '*', 'NotPrincipal': {'AWS': ['arn:aws:iam::123456789012:root']}}]:
            tree = parse_policy({'Statement': statement}, provider_detail='arn:aws-us-gov')
            self.assertCountEqual([{key: value} for key, value in statement.items()],
                                  [node['condition_json'] for node in walk(tree)
                                   if node['condition_json'] is not None])
            self.assertEqual(tree['provider_detail'], 'arn:aws-us-gov')

    def test_ec2_example_has_statement_groups_and_field_leaves(self):
        raw = (ROOT / 'examples/aws-ec2-readonly.json').read_text()
        tree = parse_policy(raw)
        self.assertEqual(tree['name'], 'Statement')
        self.assertEqual(tree['display_name'], '"Version": "2012-10-17"')
        self.assertEqual(tree['operator'], 'OR')
        self.assertEqual(tree['condition_raw'], raw)
        self.assertEqual(len(list(walk(tree))), 17)
        for group, statement in zip(tree['children'], json.loads(raw)['Statement']):
            self.assertEqual(group['operator'], 'AND')
            self.assertIsNone(group['condition_json'])
            self.assertEqual([child['condition_json'] for child in group['children']],
                             [{key: value} for key, value in statement.items()])
            self.assertTrue(all(not child['children'] for child in group['children']))
        self.assertEqual(len(tree['children'][2]['children'][1]['condition_json']['Action']), 3)

    def test_sid_sets_statement_name_and_display_name(self):
        source = json.loads((ROOT / 'examples/aws-secrets-readonly.json').read_text())
        tree = parse_policy(source)
        for group, statement in zip(tree['children'], source['Statement']):
            self.assertEqual(group['name'], statement['Sid'])
            self.assertEqual(group['display_name'], '"Sid": ' + json.dumps(statement['Sid']))
        source['Statement'][0]['Sid'] = 'quoted "Sid"'
        self.assertEqual(parse_policy(source)['children'][0]['display_name'],
                         '"Sid": ' + json.dumps('quoted "Sid"'))
        del source['Statement'][0]['Sid']
        self.assertIsNone(parse_policy(source)['children'][0]['display_name'])

    def test_statement_fields_are_conjoined(self):
        tree = parse_policy({'Statement': {'Effect': 'Allow', 'Action': 'read',
                                          'Resource': 'example',
                                          'Condition': {'Bool': {'secure': 'true'}}}})
        self.assertTrue(evaluate(tree, lambda field: True))
        for key in ('Action', 'Resource', 'Condition'):
            self.assertFalse(evaluate(tree, lambda field: key not in field))

    def test_document_wrappers_and_source_text(self):
        policy = {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}
        for source in [{'Document': policy}, {'PolicyDocument': json.dumps(policy)},
                       {'PolicyVersion': {'Document': policy}}]:
            raw = json.dumps(source, indent=4)
            self.assertEqual(parse_policy(raw)['condition_raw'], raw)

    def test_invalid_shapes_are_rejected(self):
        for source in [[], '[]', {}, {'Statement': []}, {'Statement': [None]},
                       {'Statement': {'Effect': 'Unknown', 'Action': '*', 'Resource': '*'}},
                       {'Statement': {'Effect': 'Allow', 'Noaction': '*', 'Resource': '*'}},
                       {'Statement': {'Effect': 'Allow', 'Action': '*', 'NotAction': '*', 'Resource': '*'}},
                       {'Statement': {'Effect': 'Allow', 'Action': []}},
                       {'Statement': {'Effect': 'Allow', 'Action': '*', 'Principal': {'Service': 42}}}]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_policy(source)
