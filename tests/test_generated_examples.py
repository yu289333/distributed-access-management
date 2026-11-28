import json
import unittest

from src.providers.aws.entry import parse_policy as parse_aws
from src.providers.azure.emitter import emit_policy as emit_azure
from src.tree import strip_database_ids, validate_tree
from policy_support import ROOT, walk

# The AWS snapshot is regenerated with each parser change, so it is a strict
# golden sample. The Azure RBAC snapshots predate keeping a permission array in
# one leaf; they still emit back to their source, which is what we assert.
AWS_PAIRS = (
    ('aws-secrets-readonly-db-tree.json', 'aws-secrets-readonly.json'),
)
AZURE_PAIRS = (
    ('azure-audit-vm-db-tree.json', 'azure-audit-vm.json'),
    ('azure-classic-vm-role-db-tree.json', 'azure-classic-vm-role.json'),
    ('azure-spring-role-db-tree.json', 'azure-spring-role.json'),
)


def exported(name):
    return json.loads((ROOT / 'examples/generated' / name).read_text())


class GeneratedExportTests(unittest.TestCase):
    def test_aws_export_matches_the_current_parser(self):
        for generated, source in AWS_PAIRS:
            with self.subTest(generated=generated):
                tree = strip_database_ids(exported(generated))
                validate_tree(tree)
                expected = parse_aws((ROOT / 'examples' / source).read_text(),
                                     name=tree['name'])
                self.assertEqual(tree, expected)

    def test_azure_snapshots_still_emit_to_their_sources(self):
        for generated, source in AZURE_PAIRS:
            with self.subTest(generated=generated):
                tree = strip_database_ids(exported(generated))
                validate_tree(tree)
                expected = json.loads((ROOT / 'examples' / source).read_text())
                self.assertEqual(emit_azure(tree), expected)

    def test_exported_parent_links_are_consistent(self):
        for generated, _ in AWS_PAIRS + AZURE_PAIRS:
            with self.subTest(generated=generated):
                tree = exported(generated)
                identifiers = [node['id'] for node in walk(tree)]
                self.assertEqual(len(identifiers), len(set(identifiers)))

                def check(node, parent_id):
                    self.assertEqual(node['parent_id'], parent_id)
                    for child in node.get('children', []):
                        check(child, node['id'])

                check(tree, None)

    def test_strip_is_a_pure_function(self):
        original = exported('azure-audit-vm-db-tree.json')
        before = json.dumps(original, sort_keys=True)
        stripped = strip_database_ids(original)
        self.assertEqual(json.dumps(original, sort_keys=True), before)
        for node in walk(stripped):
            self.assertNotIn('id', node)
            self.assertNotIn('parent_id', node)


if __name__ == '__main__':
    unittest.main()
