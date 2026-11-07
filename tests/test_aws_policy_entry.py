from copy import deepcopy
import json
import unittest

from src.awsPolicyEntry import parse_policy
from src.policyTree import validate_tree
from policy_support import ROOT, documents, evaluate, walk


class AwsParserTests(unittest.TestCase):
    def test_repository_examples_are_lossless(self):
        examples = list(documents('db/awsPolicies.txt'))
        examples.extend(json.loads(path.read_text()) for path in (ROOT / 'examples').glob('aws-*.json'))
        self.assertGreaterEqual(len(examples), 7)
        for source in examples:
            with self.subTest(source=source):
                original = deepcopy(source)
                tree = parse_policy(source, name='example')
                validate_tree(tree)
                statements = [node['condition_json'] for node in walk(tree)
                              if node['condition_json'] is not None]
                self.assertCountEqual(statements, source.get('Document', source)['Statement'])
                self.assertEqual(json.loads(tree['condition_raw']), source)
                self.assertEqual(source, original)
                self.assertTrue(all(node['provider'] == 'AWS' for node in walk(tree)))

    def test_explicit_deny_overrides_allow(self):
        tree = parse_policy({'Statement': [
            {'Sid': 'allow', 'Effect': 'Allow', 'Action': '*', 'Resource': '*'},
            {'Sid': 'deny', 'Effect': 'Deny', 'NotAction': 'iam:*', 'Resource': '*',
             'Condition': {'BoolIfExists': {'aws:MultiFactorAuthPresent': 'false'}}}]})
        for matched, expected in [(set(), False), ({'allow'}, True),
                                  ({'deny'}, False), ({'allow', 'deny'}, False)]:
            self.assertEqual(evaluate(tree, lambda s: s['Sid'] in matched), expected)

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
            self.assertIn(statement, [node['condition_json'] for node in walk(tree)])
            self.assertEqual(tree['provider_detail'], 'arn:aws-us-gov')

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
