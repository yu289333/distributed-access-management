import contextlib
from copy import deepcopy
import io
import json
import unittest

from src import gcpPolicyEntry
from src.gcpPolicyEntry import parse_policy
from src.policyTree import validate_tree
from policy_support import ROOT, documents, evaluate, walk


def predicate_for(hits):
    def predicate(leaf):
        if 'role' in leaf:
            return leaf['role'] in hits
        if 'member' in leaf:
            return leaf['member'] in hits
        if 'condition' in leaf:
            return 'condition' in hits
        return False
    return predicate


class GcpParserTests(unittest.TestCase):
    def test_repository_examples_are_lossless(self):
        examples = list(documents('db/gcp.txt'))
        examples.extend(json.loads(path.read_text())
                        for path in (ROOT / 'examples').glob('gcp-*.json'))
        self.assertGreaterEqual(len(examples), 2)
        for source in examples:
            with self.subTest(source=source):
                original = deepcopy(source)
                tree = parse_policy(source, name='example')
                validate_tree(tree)
                self.assertEqual(json.loads(tree['condition_raw']), source)
                self.assertEqual(source, original)
                self.assertTrue(all(node['provider'] == 'GCP' for node in walk(tree)))
                bindings = [json.loads(node['condition_raw']) for node in walk(tree)
                            if node is not tree and node['condition_raw'] is not None]
                self.assertCountEqual(bindings, source['bindings'])
                # The condition layer is deliberately left untouched.
                self.assertTrue(all(node['condition_cel'] is None for node in walk(tree)))

    def test_binding_is_role_and_any_member_and_condition(self):
        tree = parse_policy({'bindings': [{
            'role': 'roles/viewer',
            'members': ['user:alice@example.com', 'group:admins@example.com'],
            'condition': {'title': 'prod', 'expression': 'resource.name == "prod"'}}]})
        alice = {'roles/viewer', 'user:alice@example.com', 'condition'}
        for hits, expected in [
                (alice, True),
                ({'roles/viewer', 'group:admins@example.com', 'condition'}, True),
                ({'roles/viewer', 'condition'}, False),          # no member matched
                ({'roles/viewer', 'user:alice@example.com'}, False),  # condition not met
                ({'user:alice@example.com', 'condition'}, False),     # role not matched
                (set(), False)]:
            with self.subTest(hits=hits):
                self.assertEqual(evaluate(tree, predicate_for(hits)), expected)

    def test_bindings_are_unioned(self):
        tree = parse_policy({'bindings': [
            {'role': 'roles/viewer', 'members': ['user:alice@example.com']},
            {'role': 'roles/editor', 'members': ['user:bob@example.com']}]})
        for hits, expected in [
                ({'roles/viewer', 'user:alice@example.com'}, True),
                ({'roles/editor', 'user:bob@example.com'}, True),
                ({'roles/viewer', 'user:bob@example.com'}, False),
                ({'roles/editor'}, False),
                (set(), False)]:
            with self.subTest(hits=hits):
                self.assertEqual(evaluate(tree, predicate_for(hits)), expected)

    def test_condition_expression_is_preserved_as_text(self):
        source = json.loads((ROOT / 'examples' / 'gcp-iam-bindings.json').read_text())
        expression = source['bindings'][0]['condition']['expression']
        tree = parse_policy(source)
        conditions = [node['condition_json']['condition'] for node in walk(tree)
                      if node['condition_json'] and 'condition' in node['condition_json']]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0], source['bindings'][0]['condition'])
        self.assertEqual(conditions[0]['expression'], expression)
        self.assertTrue(all(node['condition_cel'] is None for node in walk(tree)))

    def test_policy_wrapper_and_provider_detail(self):
        source = {'policy': {'version': 1, 'bindings': [
            {'role': 'roles/viewer', 'members': ['user:alice@example.com']}]}}
        tree = parse_policy(source, provider_detail='cloudresourcemanager.googleapis.com')
        validate_tree(tree)
        self.assertEqual(json.loads(tree['condition_raw']), source)
        self.assertEqual(len([node for node in walk(tree)
                              if node['name'].startswith('Binding ')]), 1)
        self.assertTrue(all(node['provider_detail'] == 'cloudresourcemanager.googleapis.com'
                            for node in walk(tree)))

    def test_cli_dry_run_without_database(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(gcpPolicyEntry.main(
                [str(ROOT / 'examples' / 'gcp-iam-bindings.json'), '--dry-run']), 0)
        tree = json.loads(output.getvalue())
        validate_tree(tree)
        self.assertEqual(tree['provider'], 'GCP')

    def test_invalid_shapes_are_rejected(self):
        valid = {'role': 'roles/viewer', 'members': ['user:alice@example.com']}
        for source in [[], '[]', {}, {'bindings': []}, {'bindings': [None]},
                       {'bindings': [{'members': valid['members']}]},
                       {'bindings': [{'role': '', 'members': valid['members']}]},
                       {'bindings': [{'role': 'roles/viewer', 'members': []}]},
                       {'bindings': [{'role': 'roles/viewer', 'members': [42]}]},
                       {'bindings': [dict(valid, condition={})]},
                       {'bindings': [dict(valid, condition={'expression': ''})]},
                       {'bindings': [dict(valid, condition={'expression': 5})]}]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_policy(source)
