"""Optional PostgreSQL integration tests; temporary tables leave project data intact."""
import os
import unittest

import psycopg2

from src.backfillCel import backfill


@unittest.skipUnless(os.environ.get('DATABASE_URL'), 'DATABASE_URL required for PostgreSQL integration')
class BackfillTests(unittest.TestCase):
    def setUp(self):
        self.connection = psycopg2.connect(os.environ['DATABASE_URL'])
        with self.connection:
            with self.connection.cursor() as cursor:
                cursor.execute('CREATE TEMP TABLE policy (LIKE public.policy INCLUDING DEFAULTS)')
                cursor.execute('''INSERT INTO policy (id, parent, name, provider, provider_detail, operator, condition_json)
                                  VALUES (1, NULL, 'root', 'AWS', 'arn:aws', 'OR', NULL),
                                         (2, 1, 'action', 'AWS', 'arn:aws', 'AND', '{"Action":"ec2:Describe*"}'),
                                         (3, 1, 'raw', 'AWS', 'arn:aws', 'AND', NULL)''')
                cursor.execute('UPDATE policy SET condition_raw=%s WHERE id=3', ('{"Resource":"*"}',))

    def tearDown(self):
        self.connection.close()

    def test_preview_apply_and_repeat(self):
        self.assertEqual(len(backfill(self.connection)), 2)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT count(condition_cel) FROM policy')
            self.assertEqual(cursor.fetchone()[0], 0)
        self.assertEqual(len(backfill(self.connection, apply=True)), 2)
        self.assertEqual(backfill(self.connection, apply=True), [])
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT condition_cel FROM policy WHERE id=1')
            self.assertIsNone(cursor.fetchone()[0])
            cursor.execute('SELECT condition_origin, condition_json FROM policy WHERE id=3')
            self.assertEqual(cursor.fetchone(), ('json', {'Resource': '*'}))

    def test_replace_checks_raw_json_agreement(self):
        from src.convertConditions import convert_conditions
        backfill(self.connection, apply=True)
        with self.connection:
            with self.connection.cursor() as cursor:
                cursor.execute('UPDATE policy SET condition_raw=%s WHERE id=2', ('{"Action":"different"}',))
        with self.assertRaisesRegex(ValueError, 'different conditions'):
            convert_conditions(self.connection, apply=True, replace=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT condition_json FROM policy WHERE id=2')
            self.assertEqual(cursor.fetchone()[0], {'Action': 'ec2:Describe*'})

    def test_unsupported_source_rolls_back_entire_batch(self):
        with self.connection:
            with self.connection.cursor() as cursor:
                cursor.execute('UPDATE policy SET condition_json=%s WHERE id=3', ('{"unknown":true}',))
        with self.assertRaisesRegex(ValueError, 'Row 3'):
            backfill(self.connection, apply=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT count(condition_cel) FROM policy')
            self.assertEqual(cursor.fetchone()[0], 0)
