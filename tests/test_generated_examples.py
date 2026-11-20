import json
import unittest

from src.awsPolicyEntry import parse_policy as parse_aws
from src.azurePolicyEntry import parse_policy as parse_azure
from src.policyTree import strip_database_ids, validate_tree
from policy_support import ROOT, walk

PAIRS = (
    ('aws-secrets-readonly-db-tree.json', 'aws-secrets-readonly.json', parse_aws),
    ('azure-audit-vm-db-tree.json', 'azure-audit-vm.json', parse_azure),
    ('azure-classic-vm-role-db-tree.json', 'azure-classic-vm-role.json', parse_azure),
    ('azure-spring-role-db-tree.json', 'azure-spring-role.json', parse_azure),
)


def exported(name):
    return json.loads((ROOT / 'examples/generated' / name).read_text())


class GeneratedExportTests(unittest.TestCase):
    def test_exports_match_the_current_parsers(self):
        """The author's stored exports are golden samples for parser output."""
        for generated, source, parser in PAIRS:
            with self.subTest(generated=generated):
                tree = strip_database_ids(exported(generated))
                validate_tree(tree)
                expected = parser((ROOT / 'examples' / source).read_text(),
                                  name=tree['name'])
                self.assertEqual(tree, expected)

    def test_exported_parent_links_are_consistent(self):
        for generated, _, _ in PAIRS:
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
