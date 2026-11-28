import json
from itertools import product
import random
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


def boolean_tree(expression):
    if isinstance(expression, bool):
        return make_node(None, 'AWS', 'arn:aws', 'AND' if expression else 'OR')
    if isinstance(expression, str):
        return make_node(expression, 'AWS', 'arn:aws', condition_json={'symbol': expression})
    operator, *children = expression
    return make_node(None, 'AWS', 'arn:aws', operator,
                     children=[boolean_tree(child) for child in children])


def random_expression(rng, depth):
    if depth == 0 or rng.random() < 0.35:
        return rng.choice(('A', 'B', 'C', 'D', True, False))
    operator = rng.choice(('AND', 'OR', 'NOT'))
    if operator == 'NOT':
        return ('NOT', random_expression(rng, depth - 1))
    return (operator, random_expression(rng, depth - 1), random_expression(rng, depth - 1))


def boolean_shape(tree):
    if tree.get('condition_json') is not None:
        return tree['condition_json']['symbol']
    operator = tree['operator_onChildren']
    if not tree['children']:
        return operator == 'AND'
    return (operator, *(boolean_shape(child) for child in tree['children']))


class CanonicalizeTests(unittest.TestCase):
    def test_boolean_reductions_shrink_without_changing_truth_values(self):
        cases = [
            (('AND', 'A', True), 'A'), (('OR', 'A', False), 'A'),
            (('AND', 'A', False), False), (('OR', 'A', True), True),
            (('AND', 'A', 'A'), 'A'), (('OR', 'A', 'A'), 'A'),
            (('AND', 'A', ('NOT', 'A')), False), (('OR', 'A', ('NOT', 'A')), True),
            (('AND', 'A', ('OR', 'A', 'B')), 'A'), (('OR', 'A', ('AND', 'A', 'B')), 'A'),
            (('AND', ('NOT', 'A'), ('NOT', 'B')), ('NOT', ('OR', 'A', 'B'))),
            (('OR', ('NOT', 'A'), ('NOT', 'B')), ('NOT', ('AND', 'A', 'B'))),
            (('AND', 'A', ('NOT', False)), 'A'),
            (('AND', ('NOT', 'A'), ('NOT', ('OR', 'B', 'C'))), ('NOT', ('OR', 'A', 'B', 'C'))),
        ]
        for expression, expected in cases:
            with self.subTest(expression=expression):
                original = boolean_tree(expression)
                reduced = canonicalize(original)
                self.assertEqual(boolean_shape(reduced), expected)
                self.assertLess(len(nodes(reduced)), len(nodes(original)))
                self.assertEqual(reduced, canonicalize(reduced))
                validate_tree(reduced)
                for values in product((False, True), repeat=3):
                    assignment = dict(zip('ABC', values, strict=True))
                    def predicate(leaf):
                        return assignment[leaf['symbol']]
                    self.assertEqual(evaluate(original, predicate), evaluate(reduced, predicate))

    def test_generated_trees_keep_truth_values_and_shrink(self):
        rng = random.Random(20261128)
        for index in range(2500):
            expression = random_expression(rng, 3)
            with self.subTest(index=index, expression=expression):
                original = boolean_tree(expression)
                before = json.dumps(original, sort_keys=True)
                reduced = canonicalize(original)
                self.assertEqual(json.dumps(original, sort_keys=True), before)
                self.assertLessEqual(len(nodes(reduced)), len(nodes(original)))
                self.assertEqual(reduced, canonicalize(reduced))
                validate_tree(reduced)
                for values in product((False, True), repeat=4):
                    assignment = dict(zip('ABCD', values, strict=True))

                    def predicate(leaf):
                        return assignment[leaf['symbol']]

                    self.assertEqual(evaluate(original, predicate),
                                     evaluate(reduced, predicate))

    def test_group_with_explicit_effect_is_preserved(self):
        for effect in ('allow', 'deny'):
            with self.subTest(effect=effect):
                leaf = make_node('leaf', 'AWS', 'arn:aws', condition_json={'Action': 'read'})
                group = make_node('rule', 'AWS', 'arn:aws', children=[leaf], effect=effect)
                tree = make_node('root', 'AWS', 'arn:aws', children=[group])
                self.assertEqual(canonicalize(tree), tree)

    def test_nested_groups_of_the_same_operator_are_spliced(self):
        leaf = lambda name: make_node(name, 'AWS', 'arn:aws',
                                      condition_json={'x': name})
        tree = make_node('root', 'AWS', 'arn:aws', 'OR', children=[
            make_node('inner', 'AWS', 'arn:aws', 'OR',
                      children=[leaf('a'), leaf('b')])])
        reduced = canonicalize(tree)
        self.assertEqual(len(nodes(reduced)), 3)
        self.assertEqual(reduced['operator_onChildren'], 'OR')
        self.assertCountEqual(leaves(reduced), leaves(tree))
        for child in reduced['children']:
            self.assertNotEqual(child['operator_onChildren'], 'OR')

    def test_semantics_survive_for_every_example(self):
        for name, tree in examples():
            with self.subTest(name=name):
                reduced = canonicalize(tree)
                validate_tree(reduced)
                self.assertTrue(all(leaf in leaves(tree) for leaf in leaves(reduced)))
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
        leaf = lambda name: {'name': name, 'operator_onChildren': 'AND', 'condition_json': {'x': name}}
        tree = {'name': 'root', 'operator_onChildren': 'AND', 'children': [
            {'name': 'double', 'operator_onChildren': 'NOT', 'children': [
                {'name': 'inner', 'operator_onChildren': 'NOT', 'children': [leaf('a')]}]},
            {'name': 'true', 'operator_onChildren': 'AND', 'children': []},
            {'name': 'group', 'operator_onChildren': 'AND', 'children': [leaf('b')]},
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

    def test_root_replacement_keeps_source_and_leaf_raw_text(self):
        tree = boolean_tree(('NOT', ('NOT', 'A')))
        tree['condition_raw'] = '{"policy": "original source"}'
        leaf = tree['children'][0]['children'][0]
        leaf['condition_raw'] = '"symbol": "A"'
        reduced = canonicalize(tree)
        self.assertEqual(reduced['operator_onChildren'], 'AND')
        self.assertEqual(reduced['condition_raw'], tree['condition_raw'])
        self.assertEqual(reduced['children'][0]['condition_raw'], leaf['condition_raw'])
        validate_tree(reduced)

    def test_protected_descendant_survives_annihilator(self):
        tree = boolean_tree(('AND', False, ('OR', 'A', 'B')))
        tree['children'][1]['children'][0]['child_position'] = 0
        self.assertEqual(canonicalize(tree), tree)

    def test_invalid_trees_are_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize({'operator_onChildren': 'MAYBE', 'children': []})


if __name__ == '__main__':
    unittest.main()
