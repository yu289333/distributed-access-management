import json
import os
import unittest

import psycopg2

from src.awsPolicyEmitter import emit_policy
from src.azurePolicyEmitter import emit_policy as emit_azure
from src.awsPolicyEntry import parse_policy as parse_aws
from src.azurePolicyEntry import parse_policy as parse_azure
from src.policyTree import load_policy_tree, strip_database_ids, write_policy_tree
from policy_support import ROOT

DSN = os.environ.get('DATABASE_URL')

PAIRS = (
    ('aws-secrets-readonly-db-tree.json', 'aws-secrets-readonly.json', parse_aws),
    ('azure-audit-vm-db-tree.json', 'azure-audit-vm.json', parse_azure),
    ('azure-classic-vm-role-db-tree.json', 'azure-classic-vm-role.json', parse_azure),
    ('azure-spring-role-db-tree.json', 'azure-spring-role.json', parse_azure),
)

DELETE_SUBTREE = '''
    WITH RECURSIVE subtree AS (
        SELECT id FROM policy WHERE id = %s
        UNION ALL
        SELECT child.id FROM policy AS child
        JOIN subtree AS parent ON child.parent = parent.id
    )
    DELETE FROM policy WHERE id IN (SELECT id FROM subtree)
'''


@unittest.skipUnless(DSN, 'DATABASE_URL required for the storage round trip')
class DatabaseRoundTripTests(unittest.TestCase):
    def test_exported_trees_survive_the_database(self):
        """A stored tree reads back unchanged, and an AWS tree still emits."""
        for generated, source, parser in PAIRS:
            with self.subTest(generated=generated):
                tree = strip_database_ids(json.loads(
                    (ROOT / 'examples/generated' / generated).read_text()))
                source_text = (ROOT / 'examples' / source).read_text()
                connection = psycopg2.connect(DSN)
                root_id = None
                try:
                    root_id = write_policy_tree(connection, tree)
                    loaded = load_policy_tree(connection, root_id)
                    self.assertEqual(loaded, tree)
                    if parser is parse_aws:
                        self.assertEqual(emit_policy(loaded), json.loads(source_text))
                    else:
                        self.assertEqual(emit_azure(loaded), json.loads(source_text))
                finally:
                    if root_id is not None:
                        with connection:
                            with connection.cursor() as cursor:
                                cursor.execute(DELETE_SUBTREE, (root_id,))
                    connection.close()


if __name__ == '__main__':
    unittest.main()
