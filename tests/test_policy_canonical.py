import json
import unittest

from src.awsPolicyEntry import parse_policy as parse_aws
from src.azurePolicyEntry import parse_policy as parse_azure
from src.gcpPolicyEntry import parse_policy as parse_gcp
from src.policyTree import canonicalize, make_node, validate_tree
from policy_support import ROOT, evaluate, walk


def nodes(tree):
    return list(walk(tree))


def leaves(tree):
    return [node['condition_json'] for node in walk(tree)
            if node['condition_json'] is not None]


def examples():
    for path in sorted((ROOT / 'examples').glob('aws-*.json')):
        yield path.name, parse_aws(path.read_text())
    for path in sorted((ROOT / 'examples').glob('azure-*.json')):
        yield path.name, parse_azure(path.read_text())
    for path in sorted((ROOT / 'examples').glob('gcp-*.json')):
        yield path.name, parse_gcp(path.read_text())


def contents(expression):
    return hash(json.dumps(expression, sort_keys=True)) % 2 == 0


class CanonicalizeTests(unittest.TestCase):
    def test_nested_groups_of_the_same_operator_are_spliced(self):
        leaf = lambda name: make_node(name, 'AWS', 'arn:aws',
                                      condition_json={'x': name})
        tree = make_node('root', 'AWS', 'arn:aws', 'OR', children=[
            make_node('inner', 'AWS', 'arn:aws', 'OR',
                      children=[leaf('a'), leaf('b')])])
        reduced = canonicalize(tree)
        self.assertEqual(len(nodes(reduced)), 3)
        self.assertEqual(reduced['operator'], 'OR')
        self.assertCountEqual(leaves(reduced), leaves(tree))
        for child in reduced['children']:
            self.assertNotEqual(child['operator'], 'OR')

    def test_semantics_survive_for_every_example(self):
        for name, tree in examples():
            with self.subTest(name=name):
                reduced = canonicalize(tree)
                validate_tree(reduced)
                self.assertCountEqual(leaves(reduced), leaves(tree))
                for predicate in (lambda expression: True,
                                  lambda expression: False,
                                  contents):
                    self.assertEqual(evaluate(tree, predicate),
                                     evaluate(reduced, predicate))

    def test_reduction_is_idempotent(self):
        for name, tree in examples():
            with self.subTest(name=name):
                once = canonicalize(tree)
                self.assertEqual(canonicalize(once), once)

    def test_the_input_tree_is_not_modified(self):
        tree = parse_aws((ROOT / 'examples/aws-mfa-mandated-policy.json').read_text())
        before = json.dumps(tree, sort_keys=True)
        canonicalize(tree)
        self.assertEqual(json.dumps(tree, sort_keys=True), before)

    def test_not_not_and_empty_groups_are_removed(self):
        leaf = lambda name: {'name': name, 'operator': 'AND', 'condition_json': {'x': name}}
        tree = {'name': 'root', 'operator': 'AND', 'children': [
            {'name': 'double', 'operator': 'NOT', 'children': [
                {'name': 'inner', 'operator': 'NOT', 'children': [leaf('a')]}]},
            {'name': 'true', 'operator': 'AND', 'children': []},
            {'name': 'group', 'operator': 'AND', 'children': [leaf('b')]},
        ]}
        for node in nodes(tree):
            node.setdefault('provider', 'AWS')
            node.setdefault('provider_detail', 'arn:aws')
            node.setdefault('condition_raw', None)
            node.setdefault('condition_cel', None)
            node.setdefault('condition_json', None)
            node.setdefault('display_name', None)
            node.setdefault('comment', None)
        reduced = canonicalize(tree)
        self.assertCountEqual(leaves(reduced), [{'x': 'a'}, {'x': 'b'}])
        self.assertEqual(len(nodes(reduced)), 3)

    def test_the_root_keeps_its_source_text(self):
        source = (ROOT / 'examples/aws-ec2-readonly.json').read_text()
        tree = parse_aws(source)
        reduced = canonicalize(tree)
        self.assertEqual(reduced['condition_raw'], source)
        self.assertEqual(reduced['name'], tree['name'])

    def test_invalid_trees_are_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize({'operator': 'MAYBE', 'children': []})


if __name__ == '__main__':
    unittest.main()
