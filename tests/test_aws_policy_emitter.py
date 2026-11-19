from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from src.awsPolicyEmitter import emit_aws, emit_policy, main
from src.awsPolicyEntry import parse_policy
from src.policyTree import make_node, validate_tree
from policy_support import ROOT, documents, evaluate, walk


def source_statements(source):
    container = source
    for key in ('Document', 'PolicyVersion'):
        if key in container:
            container = container[key]
            if key == 'PolicyVersion' and 'Document' in container:
                container = container['Document']
    if 'PolicyDocument' in container:
        wrapped = container['PolicyDocument']
        container = json.loads(wrapped) if isinstance(wrapped, str) else wrapped
    statements = container['Statement']
    return statements if isinstance(statements, list) else [statements]


def all_aws_samples():
    yield from documents('db/awsPolicies.txt')
    for path in (ROOT / 'examples').glob('aws-*.json'):
        yield json.loads(path.read_text())


class AwsEmitterTests(unittest.TestCase):
    def test_repository_samples_round_trip_losslessly(self):
        samples = list(all_aws_samples())
        self.assertGreaterEqual(len(samples), 7)
        for source in samples:
            with self.subTest(source=source):
                original = deepcopy(source)
                document = emit_policy(parse_policy(source))
                self.assertCountEqual(document['Statement'], source_statements(source))
                self.assertEqual(source, original)
                validate_tree(parse_policy(document))

    def test_examples_are_reconstructed_exactly(self):
        for path in (ROOT / 'examples').glob('aws-*.json'):
            with self.subTest(path=path.name):
                source = json.loads(path.read_text())
                self.assertEqual(emit_policy(parse_policy(source)), source)

    def test_order_and_deny_semantics_survive_a_round_trip(self):
        source = {'Version': '2012-10-17', 'Id': 'mixed', 'Statement': [
            {'Sid': 'allow-read', 'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': '*'},
            {'Sid': 'deny-prod', 'Effect': 'Deny', 'Action': 's3:*',
             'Resource': 'arn:aws:s3:::prod-*'},
            {'Sid': 'allow-write', 'Effect': 'Allow', 'Action': 's3:PutObject',
             'Resource': 'arn:aws:s3:::dev-*',
             'Condition': {'StringLike': {'aws:PrincipalTag/team': 'prod-*'}}}]}
        tree = parse_policy(source)
        document = emit_policy(tree)
        self.assertEqual(document, source)
        rebuilt = parse_policy(document)
        for matched in (set(), {'allow-read'}, {'allow-write'}, {'deny-prod'},
                        {'allow-read', 'deny-prod'}, {'allow-read', 'allow-write', 'deny-prod'}):
            with self.subTest(matched=matched):
                self.assertEqual(evaluate(tree, lambda s: s['Sid'] in matched),
                                 evaluate(rebuilt, lambda s: s['Sid'] in matched))

    def test_deny_only_policy_round_trips(self):
        source = {'Statement': {'Effect': 'Deny', 'Action': '*', 'Resource': '*'}}
        document = emit_policy(parse_policy(source))
        self.assertEqual(document['Statement'], [source['Statement']])
        self.assertFalse(evaluate(parse_policy(document), lambda s: True))

    def test_api_wrappers_are_normalised(self):
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': '*'}]}
        for source in ({'Document': policy},
                       {'PolicyDocument': json.dumps(policy)},
                       {'PolicyVersion': {'Document': policy}}):
            with self.subTest(source=source):
                document = emit_policy(parse_policy(source))
                self.assertEqual(list(document), ['Version', 'Statement'])
                self.assertEqual(document, policy)

    def test_tree_without_raw_text_still_emits(self):
        source = {'Statement': [
            {'Effect': 'Allow', 'Action': 'ec2:Describe*', 'Resource': '*'},
            {'Effect': 'Deny', 'Action': 'ec2:*', 'Resource': 'arn:aws:ec2:::prod'}]}
        tree = parse_policy(source)
        for node in walk(tree):
            node['condition_raw'] = None
        document = emit_policy(tree)
        self.assertCountEqual(document['Statement'], source['Statement'])
        self.assertEqual(list(document), ['Statement'])
        self.assertEqual(document['Statement'][0]['Effect'], 'Allow')
        self.assertEqual(document['Statement'][1]['Effect'], 'Deny')

    def test_tree_edits_are_reflected_not_copied(self):
        source = {'Version': '2012-10-17', 'Statement': [
            {'Sid': 'a', 'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': '*'},
            {'Sid': 'b', 'Effect': 'Allow', 'Action': 's3:Put*', 'Resource': '*'},
            {'Sid': 'c', 'Effect': 'Allow', 'Action': 's3:List*', 'Resource': '*'}]}
        tree = parse_policy(source)
        tree['children'].pop(1)
        document = emit_policy(tree)
        self.assertEqual([s['Sid'] for s in document['Statement']], ['a', 'c'])

        edited = parse_policy(source)
        edited['children'][0]['condition_json']['Action'] = 's3:GetObject'
        self.assertEqual(emit_policy(edited)['Statement'][0]['Action'], 's3:GetObject')

    def test_emit_aws_is_an_alias(self):
        source = {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}
        self.assertEqual(emit_aws(parse_policy(source)), emit_policy(parse_policy(source)))

    def test_non_aws_trees_are_rejected(self):
        tree = parse_policy({'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}})
        tree['provider'] = 'Azure'
        with self.assertRaises(ValueError):
            emit_policy(tree)
        foreign = make_node('foreign', 'GCP', 'iam.googleapis.com', 'OR')
        with self.assertRaises(ValueError):
            emit_policy(foreign)

    def test_unexpected_tree_shapes_are_rejected(self):
        base = {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}
        xor_tree = parse_policy(base)
        xor_tree['operator'] = 'XOR'
        with self.assertRaises(ValueError):
            emit_policy(xor_tree)

        and_tree = parse_policy(base)
        and_tree['operator'] = 'AND'
        and_tree['children'] = [and_tree['children'][0], and_tree['children'][0].copy()]
        with self.assertRaises(ValueError):
            emit_policy(and_tree)

        bad_leaf = parse_policy(base)
        bad_leaf['children'][0]['condition_json'] = {'Effect': 'Maybe', 'Action': '*'}
        with self.assertRaises(ValueError):
            emit_policy(bad_leaf)

        empty_leaf = parse_policy(base)
        empty_leaf['children'][0]['condition_json'] = None
        with self.assertRaises(ValueError):
            emit_policy(empty_leaf)

    def test_cli_reads_a_dry_run_tree(self):
        source = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'ec2:Describe*', 'Resource': '*'}]}
        tree_text = json.dumps(parse_policy(source))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tree.json'
            path.write_text(tree_text)
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(path)]), 0)
        self.assertEqual(json.loads(output.getvalue()), source)
