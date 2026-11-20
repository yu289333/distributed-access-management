import json
import unittest

from src.awsPolicyEntry import parse_policy as parse_aws
from src.awsToAzure import translate, translate_tree
from src.azurePolicyEntry import parse_policy as parse_azure
from src.azurePolicyEmitter import emit_policy as emit_azure
from src.policyTree import validate_tree
from policy_support import ROOT


class AwsToAzureTests(unittest.TestCase):
    def test_ec2_readonly_becomes_compute_and_network_reads(self):
        tree = parse_aws((ROOT / 'examples/aws-ec2-readonly.json').read_text())
        document, report = translate(tree, name='EC2 read only')
        actions = document['permissions'][0]['actions']
        self.assertEqual(document['roleName'], 'EC2 read only')
        self.assertEqual(set(actions), {'Microsoft.Compute/*/read',
                                        'Microsoft.Network/*/read',
                                        'Microsoft.Insights/*/read'})
        self.assertEqual(report['unmapped'], [])
        self.assertEqual(report['warnings'], [])

    def test_explicit_deny_becomes_not_actions_with_a_warning(self):
        policy = {'Statement': [
            {'Effect': 'Allow', 'Action': 'ec2:Describe*', 'Resource': '*'},
            {'Effect': 'Deny', 'Action': 'ec2:Delete*', 'Resource': '*'}]}
        document, report = translate(parse_aws(policy), name='deny demo')
        self.assertEqual(document['permissions'][0]['actions'],
                         ['Microsoft.Compute/*/read'])
        self.assertEqual(document['permissions'][0]['notActions'],
                         ['Microsoft.Compute/*/delete'])
        self.assertTrue(any('notActions' in warning for warning in report['warnings']))

    def test_unknown_service_is_reported_not_dropped_silently(self):
        policy = {'Statement': {'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                'Resource': '*'}}
        document, report = translate(parse_aws(policy))
        self.assertEqual(document['permissions'][0]['actions'], [])
        self.assertEqual(report['unmapped'], ['sts:AssumeRole'])

    def test_resource_arns_are_reported(self):
        tree = parse_aws((ROOT / 'examples/aws-secrets-readonly.json').read_text())
        document, report = translate(tree)
        self.assertEqual(document['permissions'][0]['actions'],
                         ['Microsoft.KeyVault/*/read'])
        self.assertTrue(any('Resource ARNs' in warning for warning in report['warnings']))

    def test_translation_flows_through_the_azure_tree(self):
        tree = parse_aws((ROOT / 'examples/aws-ec2-readonly.json').read_text())
        document, _ = translate(tree, name='translated')
        azure_tree, _ = translate_tree(tree, name='translated')
        validate_tree(azure_tree)
        self.assertEqual(azure_tree['provider'], 'Azure')
        self.assertEqual(azure_tree['provider_detail'],
                         'Microsoft.Authorization/roleDefinitions')
        self.assertEqual(emit_azure(azure_tree), document)
        self.assertEqual(emit_azure(parse_azure(json.dumps(document))), document)

    def test_edits_in_the_aws_tree_are_translated(self):
        tree = parse_aws((ROOT / 'examples/aws-ec2-readonly.json').read_text())
        first = tree['children'][0]['children']
        action = next(child for child in first if 'Action' in child['condition_json'])
        action['condition_json']['Action'] = 's3:GetObject'
        document, _ = translate(tree)
        self.assertIn('Microsoft.Storage/*/read', document['permissions'][0]['actions'])


if __name__ == '__main__':
    unittest.main()
