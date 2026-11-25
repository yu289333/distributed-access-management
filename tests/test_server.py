import json
import os
import threading
import unittest
import urllib.error
import urllib.request

import psycopg2

from src.server import create_server
from policy_support import ROOT

DSN = os.environ.get('DATABASE_URL')


def call(url, *, method='GET', body=None):
    data = json.dumps(body).encode('utf-8') if body is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={'Content-Type': 'application/json'} if data else {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


@unittest.skipUnless(DSN, 'DATABASE_URL required for the HTTP service')
class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server('127.0.0.1', 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = 'http://127.0.0.1:%d' % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def tearDown(self):
        for root_id in getattr(self, 'created', []):
            with psycopg2.connect(DSN) as connection, connection.cursor() as cursor:
                cursor.execute('''
                    WITH RECURSIVE subtree AS (
                        SELECT id FROM policy WHERE id = %s
                        UNION ALL
                        SELECT child.id FROM policy AS child
                        JOIN subtree AS parent ON child.parent = parent.id
                    )
                    DELETE FROM policy WHERE id IN (SELECT id FROM subtree)
                ''', (root_id,))

    def test_healthz(self):
        status, payload = call(self.base + '/healthz')
        self.assertEqual(status, 200)
        self.assertEqual(payload, {'status': 'ok'})

    def test_parse_store_load_and_emit(self):
        source = json.loads((ROOT / 'examples/aws-ec2-readonly.json').read_text())
        self.created = []
        for option, expected in (('', 'Action.matches("^ec2:Describe.*$")'), ('&cel=false', None)):
            with self.subTest(option=option):
                status, created = call(
                    self.base + '/policies?provider=aws&name=ec2-readonly' + option,
                    method='POST', body=source)
                self.assertEqual(status, 201)
                self.created.append(created['id'])
                self.assertEqual(created['provider'], 'AWS')
                self.assertGreater(created['nodes'], 1)

                status, payload = call(self.base + '/policies/%d' % created['id'])
                self.assertEqual(status, 200)
                self.assertEqual(payload['document'], source)
                tree = payload['tree']
                self.assertEqual(tree['name'], 'ec2-readonly')
                self.assertEqual(len(tree['children']), 4)
                self.assertEqual(tree['condition_raw'], json.dumps(source))
                self.assertEqual(tree['children'][0]['children'][1]['condition_cel'], expected)

    def test_azure_tree_has_its_document(self):
        source = json.loads((ROOT / 'examples/azure-classic-vm-role.json').read_text())
        status, created = call(self.base + '/policies?provider=azure', method='POST', body=source)
        self.assertEqual(status, 201)
        self.created = [created['id']]
        status, payload = call(self.base + '/policies/%d' % created['id'])
        self.assertEqual(status, 200)
        self.assertEqual(payload['document'], source)

    def test_canonical_trees_are_smaller_or_equal(self):
        source = json.loads((ROOT / 'examples/azure-audit-vm.json').read_text())
        status, created = call(self.base + '/policies?provider=azure', method='POST', body=source)
        self.assertEqual(status, 201)
        self.created = [created['id']]
        _, plain = call(self.base + '/policies/%d' % created['id'])
        _, reduced = call(self.base + '/policies/%d?canonical=1' % created['id'])
        self.assertLessEqual(self._nodes(reduced['tree']), self._nodes(plain['tree']))

    def test_bad_requests(self):
        self.assertEqual(400, call(self.base + '/policies?provider=nope', method='POST',
                                   body={'Statement': []})[0])
        self.assertEqual(400, call(self.base + '/policies?provider=aws', method='POST',
                                   body=[])[0])
        self.assertEqual(404, call(self.base + '/policies/999999999')[0])
        self.assertEqual(404, call(self.base + '/nope')[0])

    @staticmethod
    def _nodes(tree):
        return 1 + sum(ServerTests._nodes(child) for child in tree.get('children', []))


if __name__ == '__main__':
    unittest.main()
