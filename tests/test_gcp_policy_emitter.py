from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from src.awsPolicyEntry import parse_policy as parse_aws
from src.gcpPolicyEmitter import emit_gcp, emit_policy, main
from src.gcpPolicyEntry import parse_policy
from src.policyTree import canonicalize
from policy_support import ROOT


class GcpEmitterTests(unittest.TestCase):
    def test_example_round_trips_exactly(self):
        source = (ROOT / 'examples/gcp-iam-bindings.json').read_text()
        self.assertEqual(emit_policy(parse_policy(source)), json.loads(source))

    def test_edits_are_reflected(self):
        tree = parse_policy((ROOT / 'examples/gcp-iam-bindings.json').read_text())
        role = tree['children'][0]['children'][0]
        role['condition_json']['role'] = 'roles/storage.admin'
        role['condition_raw'] = None
        document = emit_policy(tree)
        self.assertEqual(document['bindings'][0]['role'], 'roles/storage.admin')

    def test_unified_access_rules_round_trip_in_source_order(self):
        principal = 'principal://goog/subject/alice@example.com'
        source = {'displayName': 'Compute policy', 'details': {'rules': [
            {'effect': 'ALLOW', 'principals': [principal],
             'operation': {'permissions': ['role:roles/compute.admin']}},
            {'effect': 'DENY', 'principals': [principal],
             'operation': {'permissions': ['compute.googleapis.com/instances.delete']}},
            {'effect': 'ALLOW', 'principals': [principal],
             'operation': {'permissions': ['compute.googleapis.com/instances.get']}},
        ]}}
        tree = canonicalize(parse_policy(json.dumps(source)))
        self.assertEqual(emit_policy(tree), source)
        allow, excluded = tree['children']
        operation = excluded['children'][0]['children'][2]
        operation['condition_json']['operation']['permissions'] = ['compute.googleapis.com/instances.stop']
        operation['condition_raw'] = None
        tree['children'] = [excluded, allow]
        emitted = emit_policy(tree)
        source['details']['rules'][1]['operation']['permissions'] = ['compute.googleapis.com/instances.stop']
        self.assertEqual(emitted, source)

    def test_non_gcp_trees_are_rejected(self):
        tree = parse_aws({'Statement': {'Effect': 'Allow', 'Action': '*',
                                        'Resource': '*'}})
        with self.assertRaises(ValueError):
            emit_policy(tree)

    def test_emit_gcp_is_an_alias(self):
        source = (ROOT / 'examples/gcp-iam-bindings.json').read_text()
        self.assertEqual(emit_gcp(parse_policy(source)), emit_policy(parse_policy(source)))

    def test_cli_reads_a_dry_run_tree(self):
        source = json.loads((ROOT / 'examples/gcp-iam-bindings.json').read_text())
        tree_text = json.dumps(parse_policy(json.dumps(source)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tree.json'
            path.write_text(tree_text)
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(path)]), 0)
        self.assertEqual(json.loads(output.getvalue()), source)


if __name__ == '__main__':
    unittest.main()
