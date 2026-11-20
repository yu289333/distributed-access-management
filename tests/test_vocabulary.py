import unittest

from src import morph
from src.awsPolicyEntry import parse_policy
from src.awsVocabulary import decode
from src.azureVocabulary import encode
from src.vocabulary import atom
from policy_support import ROOT


class VocabularyTests(unittest.TestCase):
    def test_aws_decodes_to_neutral_atoms(self):
        self.assertEqual(decode('ec2:Describe*'), atom('compute', 'read'))
        self.assertEqual(decode('s3:GetObject'), atom('storage', 'read'))
        self.assertEqual(decode('logs:CreateLogGroup'), atom('logging', 'write'))
        self.assertEqual(decode('ec2:Delete*'), atom('compute', 'delete'))
        self.assertEqual(decode('ec2:*'), atom('compute', 'all'))
        self.assertIsNone(decode('sts:AssumeRole'))

    def test_azure_encodes_atoms(self):
        self.assertEqual(encode(atom('compute', 'read')), 'Microsoft.Compute/*/read')
        self.assertEqual(encode(atom('storage', 'write')), 'Microsoft.Storage/*/write')
        self.assertEqual(encode(atom('identity', 'all')), 'Microsoft.Authorization/*')

    def test_a_new_target_only_needs_an_adapter_pair(self):
        # The point of the refactor: a target is an encoder plus a document
        # builder. The AWS decode side is reused untouched.
        def demo_encode(neutral):
            return f"{neutral['domain']}:{neutral['verb']}"

        def demo_build(name, actions, not_actions):
            return {'target': 'demo', 'name': name,
                    'actions': actions, 'notActions': not_actions}

        morph.register_target('demo', demo_encode, demo_build)
        try:
            tree = parse_policy((ROOT / 'examples/aws-ec2-readonly.json').read_text())
            document, report = morph.translate(tree, target='demo', name='demo')
        finally:
            morph.TARGETS.pop('demo', None)
        self.assertEqual(document['target'], 'demo')
        self.assertEqual(document['actions'],
                         ['compute:read', 'network:read', 'monitoring:read'])
        self.assertEqual(report['unmapped'], [])

    def test_azure_target_is_unchanged(self):
        tree = parse_policy((ROOT / 'examples/aws-ec2-readonly.json').read_text())
        document, _ = morph.translate(tree, name='x')
        self.assertEqual(document['permissions'][0]['actions'],
                         ['Microsoft.Compute/*/read', 'Microsoft.Network/*/read',
                          'Microsoft.Insights/*/read'])

    def test_unknown_source_or_target_is_rejected(self):
        tree = parse_policy({'Statement': {'Effect': 'Allow', 'Action': '*',
                                           'Resource': '*'}})
        with self.assertRaises(ValueError):
            morph.translate(tree, source='oracle')
        with self.assertRaises(ValueError):
            morph.translate(tree, target='oracle')


if __name__ == '__main__':
    unittest.main()
