import os
import unittest

import psycopg2

from policy_support import ROOT

DSN = os.environ.get('DATABASE_URL')
MIGRATIONS = ROOT / 'db' / 'migrations'

# Schema before 002_policy_fields.sql: operator + condition_origin, XOR present,
# no effect/child_position/SUBTRACT.
OLD_SCHEMA = '''
CREATE TYPE setOperator AS ENUM ('OR', 'AND', 'XOR', 'NOT');
CREATE TABLE policy (
    id serial primary key,
    parent integer references policy(id),
    name text,
    display_name text,
    comment text,
    provider text,
    provider_detail text,
    operator setOperator not null default 'AND',
    condition_raw text,
    condition_cel text,
    condition_json jsonb,
    condition_origin text
);
'''


def apply(connection, *names):
    with connection.cursor() as cursor:
        for name in names:
            cursor.execute((MIGRATIONS / name).read_text(encoding='utf-8'))


def fresh(connection, schema):
    with connection.cursor() as cursor:
        cursor.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        cursor.execute(f'CREATE SCHEMA {schema}')
        cursor.execute(f'SET search_path TO {schema}')
        cursor.execute(OLD_SCHEMA)


def drop(connection, schema):
    with connection.cursor() as cursor:
        cursor.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')


def columns(connection, schema):
    with connection.cursor() as cursor:
        cursor.execute('''SELECT column_name FROM information_schema.columns
                          WHERE table_schema = %s AND table_name = 'policy' ''',
                       (schema,))
        return {row[0] for row in cursor.fetchall()}


def enum_labels(connection, schema):
    with connection.cursor() as cursor:
        cursor.execute('''SELECT e.enumlabel FROM pg_enum e
                          JOIN pg_type t ON t.oid = e.enumtypid
                          JOIN pg_namespace n ON n.oid = t.typnamespace
                          WHERE t.typname = 'setoperator' AND n.nspname = %s''',
                       (schema,))
        return {row[0] for row in cursor.fetchall()}


def seed(connection):
    """Insert a root OR, a statement AND, and an Effect field leaf."""
    with connection.cursor() as cursor:
        cursor.execute('''INSERT INTO policy (id, name, provider, provider_detail,
                            operator, condition_origin)
                          VALUES (1, 'root', 'AWS', 'arn:aws', 'OR', 'json')''')
        cursor.execute('''INSERT INTO policy (id, parent, name, provider, provider_detail,
                            operator)
                          VALUES (2, 1, 'Statement', 'AWS', 'arn:aws', 'AND')''')
        cursor.execute('''INSERT INTO policy (id, parent, name, provider, provider_detail,
                            operator, condition_json, condition_origin)
                          VALUES (3, 2, 'Effect', 'AWS', 'arn:aws', 'AND',
                                  '{"Effect": "Allow"}'::jsonb, 'json')''')


def seed_subtract(connection):
    """Insert a SUBTRACT node with operands at positions 0 and 1."""
    with connection.cursor() as cursor:
        cursor.execute('''INSERT INTO policy (id, name, provider, provider_detail,
                                "operator_onChildren")
                          VALUES (4, 'subtract', 'AWS', 'arn:aws', 'SUBTRACT')''')
        cursor.execute('''INSERT INTO policy (id, parent, name, provider, provider_detail,
                                "operator_onChildren", child_position)
                          VALUES (5, 4, 'a', 'AWS', 'arn:aws', 'AND', 0),
                                 (6, 4, 'b', 'AWS', 'arn:aws', 'AND', 1)''')
        # Explicit ids do not advance the serial sequence; migration 005 inserts
        # the NOT wrapper with nextval().
        cursor.execute("SELECT setval(pg_get_serial_sequence('policy', 'id'), 100)")


def assert_upgraded(test, connection, schema):
    present = columns(connection, schema)
    test.assertIn('operator_onChildren', present)
    test.assertIn('condition_raw_type', present)
    test.assertIn('effect', present)
    test.assertIn('child_position', present)
    test.assertNotIn('operator', present)
    test.assertNotIn('condition_origin', present)
    test.assertNotIn('XOR', enum_labels(connection, schema))

    with connection.cursor() as cursor:
        cursor.execute('SELECT effect FROM policy WHERE id = 2')
        test.assertEqual(cursor.fetchone()[0], 'allow')
        cursor.execute('SELECT "operator_onChildren" FROM policy WHERE id = 4')
        test.assertEqual(cursor.fetchone()[0], 'AND')
        cursor.execute('''SELECT id, parent, child_position FROM policy
                          WHERE parent = 4 AND "operator_onChildren" = 'NOT' ''')
        not_id, parent, position = cursor.fetchone()
        test.assertEqual((parent, position), (4, 1))
        cursor.execute('SELECT parent, child_position FROM policy WHERE id = 6')
        test.assertEqual(cursor.fetchone(), (not_id, None))
        cursor.execute('SELECT parent, child_position FROM policy WHERE id = 5')
        test.assertEqual(cursor.fetchone(), (4, 0))
    test.assertNotIn('SUBTRACT', enum_labels(connection, schema))


@unittest.skipUnless(DSN, 'DATABASE_URL required for migration tests')
class MigrationTests(unittest.TestCase):
    def test_upgrade_path(self):
        schema = 'migration_test_upgrade'
        connection = psycopg2.connect(DSN)
        connection.autocommit = True
        try:
            fresh(connection, schema)
            seed(connection)
            apply(connection, '002_policy_fields.sql', '003_remove_xor.sql')
            with connection.cursor() as cursor:
                cursor.execute('SELECT effect FROM policy WHERE id = 2')
                self.assertEqual(cursor.fetchone()[0], 'allow')
            apply(connection, '004_subtract_operands.sql')
            seed_subtract(connection)
            apply(connection, '005_replace_subtract.sql')
            assert_upgraded(self, connection, schema)
        finally:
            drop(connection, schema)
            connection.close()

    def test_upgrade_path_in_one_transaction(self):
        # Matches the documented `psql -1 -f 002 ... -f 005` invocation.
        schema = 'migration_test_transaction'
        connection = psycopg2.connect(DSN)
        connection.autocommit = False
        try:
            fresh(connection, schema)
            seed(connection)
            apply(connection, '002_policy_fields.sql', '003_remove_xor.sql')
            apply(connection, '004_subtract_operands.sql')
            seed_subtract(connection)
            apply(connection, '005_replace_subtract.sql')
            connection.commit()
            assert_upgraded(self, connection, schema)
        finally:
            connection.rollback()
            connection.autocommit = True
            drop(connection, schema)
            connection.close()

    def test_remove_xor_stops_on_existing_rows(self):
        schema = 'migration_test_xor'
        connection = psycopg2.connect(DSN)
        connection.autocommit = True
        try:
            fresh(connection, schema)
            apply(connection, '002_policy_fields.sql')
            with connection.cursor() as cursor:
                cursor.execute('''INSERT INTO policy (id, name, provider, provider_detail,
                                        "operator_onChildren")
                                  VALUES (1, 'xor', 'AWS', 'arn:aws', 'XOR')''')
            with self.assertRaisesRegex(psycopg2.Error, 'Cannot remove XOR'):
                apply(connection, '003_remove_xor.sql')
        finally:
            drop(connection, schema)
            connection.close()


if __name__ == '__main__':
    unittest.main()
