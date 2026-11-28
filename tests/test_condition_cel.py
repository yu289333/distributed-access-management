import json
import unittest
from pathlib import Path

from celpy import Environment, json_to_cel
from src.conditions.format import cel_activation
from src.conditionExpression import condition_to_cel, populate_condition_cel
from src.awsPolicyEntry import parse_policy
from src.policyTree import make_node


def run(expression, request=None, context=None, fields=None, resource=None):
    env = Environment()
    program = env.program(env.compile(expression))
    activation = cel_activation(request or {}, context, fields, resource)
    if resource and 'type' in resource:
        activation['type'] = resource['type']
    return bool(program.evaluate({k: json_to_cel(v) for k, v in activation.items()}))


class CelTests(unittest.TestCase):
    def aws(self, source):
        return condition_to_cel(source, provider='AWS')

    def test_aws_fields_preserve_names_values_and_types(self):
        examples = [
            {'Effect': 'Allow'}, {'Effect': 'Deny'},
            {'Action': ['ec2:Describe*', 's3:Get?bject']},
            {'Action': 'secretsmanager:GetRandomPassword'},
            {'Resource': '*'},
            {'Resource': 'arn:aws:iam::*:user/${aws:username}'},
            {'NotAction': ['iam:*']}, {'NotResource': 'example'},
            {'Principal': {'Service': 'lambda.amazonaws.com'}},
            {'NotPrincipal': {'AWS': ['arn:aws:iam::123:root']}},
            {'Condition': {'BoolIfExists': {'aws:MultiFactorAuthPresent': 'false'}}},
            {'Condition': {'IpAddress': {'aws:SourceIp': '10.0.0.0/8'}}}]
        for source in examples:
            with self.subTest(source=source):
                key, value = next(iter(source.items()))
                expression = self.aws(source)
                self.assertEqual(expression, key + ' == ' + json.dumps(value))
                self.assertNotIn('request.', expression)
                self.assertNotIn('.matches(', expression)
                env = Environment()
                program = env.program(env.compile(expression))
                self.assertTrue(program.evaluate({key: json_to_cel(value)}))
                other = [] if isinstance(value, list) else {} if isinstance(value, dict) else 'different'
                self.assertFalse(program.evaluate({key: json_to_cel(other)}))

    def test_legacy_statement_and_raw_fallback(self):
        source = {'Sid': 'example', 'Effect': 'Deny', 'Action': 's3:*', 'Resource': '*'}
        expression = condition_to_cel(condition_raw=json.dumps(source), provider='AWS')
        env = Environment()
        program = env.program(env.compile(expression))
        self.assertTrue(program.evaluate({k: json_to_cel(v) for k,v in source.items()}))
        with self.assertRaises(ValueError):
            condition_to_cel({'Effect': 'Allow'}, 'invalid raw', provider='AWS')

    def test_aws_scalar_action_globs_match_entire_strings(self):
        expression = self.aws({'Action': 's3:*'})
        self.assertEqual(expression, 'Action.matches("^s3:.*$")')
        env = Environment()
        program = env.program(env.compile(expression))
        self.assertTrue(program.evaluate({'Action': json_to_cel('s3:GetObject')}))
        self.assertFalse(program.evaluate({'Action': json_to_cel('ec2:DescribeInstances')}))
        self.assertFalse(program.evaluate({'Action': json_to_cel('other:s3:GetObject')}))

        program = env.program(env.compile(self.aws({'Action': 's3:Get.*Object'})))
        self.assertTrue(program.evaluate({'Action': json_to_cel('s3:Get.myObject')}))
        self.assertFalse(program.evaluate({'Action': json_to_cel('s3:GetXmyObject')}))

    def test_azure_planes_and_fields(self):
        expression = condition_to_cel({'notActions': ['*/write']}, provider='Azure',
                                     provider_detail='Microsoft.Authorization/roleDefinitions')
        self.assertEqual(expression, 'notActions == ["*/write"]')
        env = Environment()
        program = env.program(env.compile(expression))
        self.assertTrue(program.evaluate({'notActions': json_to_cel(['*/write'])}))
        self.assertFalse(program.evaluate({'notActions': json_to_cel(['X/write'])}))
        for source, fields, expected in [({'field': 'type', 'equals': 'VM'}, {'type': 'VM'}, True),
                                         ({'field': 'type', 'equals': 'VM'}, {'type': 'Other'}, False),
                                         ({'field': 'type', 'exists': 'false'}, {}, True)]:
            expression = condition_to_cel(source, provider='Azure',
                                         provider_detail='Microsoft.Authorization/policyDefinitions')
            self.assertEqual(run(expression, resource=fields), expected)

    def test_azure_parser_populates_equals_and_preserves_not(self):
        from src.azurePolicyEntry import parse_policy as azure
        path = Path(__file__).resolve().parents[1] / 'examples/azure-audit-vm.json'
        tree = azure(path.read_text())
        applicability, outcome = tree['children']
        type_leaf, negation = applicability['children']
        self.assertEqual(negation['operator_onChildren'], 'NOT')
        encryption_leaf = negation['children'][0]
        expression = encryption_leaf['condition_cel']
        self.assertEqual(expression, 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.encryptionSettings.enabled == true')
        self.assertNotIn('!', expression)
        self.assertEqual(type_leaf['condition_cel'], 'type == "Microsoft.Compute/virtualMachines"')
        self.assertTrue(run(type_leaf['condition_cel'], resource={'type': 'Microsoft.Compute/virtualMachines'}))
        self.assertFalse(run(type_leaf['condition_cel'], resource={'type': 'Other'}))
        self.assertIsNone(negation['condition_cel'])
        self.assertEqual(outcome['children'][0]['condition_cel'], 'effect == "audit"')

    def test_azure_effect_expression_uses_string_literal(self):
        for value in ('audit', 'deny', 'quoted "effect"'):
            expression = condition_to_cel({'effect': value}, provider='Azure',
                                         provider_detail='Microsoft.Authorization/policyDefinitions')
            self.assertEqual(expression, 'effect == ' + json.dumps(value))
            env = Environment()
            program = env.program(env.compile(expression))
            self.assertTrue(program.evaluate({'effect': json_to_cel(value)}))
            self.assertFalse(program.evaluate({'effect': json_to_cel('other')}))

    def test_azure_severity_and_type_use_top_level_variables(self):
        for key, value in [('severity', 'Critical'), ('type', 'Microsoft.Compute/virtualMachines')]:
            expression = condition_to_cel({key: value}, provider='Azure',
                                         provider_detail='Microsoft.Authorization/policyDefinitions')
            self.assertEqual(expression, key + ' == ' + json.dumps(value))
            env = Environment()
            program = env.program(env.compile(expression))
            self.assertTrue(program.evaluate({key: json_to_cel(value)}))
            self.assertFalse(program.evaluate({key: json_to_cel('other')}))

    def test_scope_list_equality(self):
        for scopes in (['/'], ['/', '/abc'], []):
            expression = condition_to_cel({'assignableScopes': scopes}, provider='Azure',
                                         provider_detail='Microsoft.Authorization/roleDefinitions')
            self.assertEqual(expression, 'assignableScopes == ' + json.dumps(scopes))
            env = Environment()
            program = env.program(env.compile(expression))
            self.assertTrue(program.evaluate({'assignableScopes': json_to_cel(scopes)}))
            self.assertFalse(program.evaluate({'assignableScopes': json_to_cel(['/other'])}))

    def test_azure_permission_arrays_preserve_json_field_names(self):
        from src.azurePolicyEntry import parse_policy as azure
        path = Path(__file__).resolve().parents[1] / 'examples/azure-spring-role.json'
        tree = azure(path.read_text())
        def check(node):
            expression = node['condition_json']
            if expression is not None:
                key, value = next(iter(expression.items()))
                self.assertEqual(node['condition_cel'], key + ' == ' + json.dumps(value))
                self.assertNotIn('request.', node['condition_cel'])
                env = Environment()
                program = env.program(env.compile(node['condition_cel']))
                self.assertTrue(program.evaluate({key: json_to_cel(value)}))
            for child in node['children']:
                check(child)
        check(tree)
        for key in ('actions', 'notActions', 'dataActions', 'notDataActions'):
            expression = condition_to_cel({key: []}, provider='Azure',
                                         provider_detail='Microsoft.Authorization/roleDefinitions')
            self.assertEqual(expression, key + ' == []')

    def test_all_aws_example_leaves_compile(self):
        for path in (Path(__file__).resolve().parents[1] / 'examples').glob('aws-*.json'):
            if path.name.endswith('-sql.json'):
                continue
            tree = parse_policy(path.read_text())
            def check(node):
                if node['children']:
                    self.assertIsNone(node['condition_cel'])
                    for child in node['children']:
                        check(child)
                else:
                    self.assertIsNotNone(node['condition_cel'], node)
                    Environment().compile(node['condition_cel'])
            check(tree)

    def test_unsupported_conditions_are_explicit(self):
        source = {'UnknownField': 'value'}
        with self.assertRaisesRegex(ValueError, 'Unsupported AWS field'):
            self.aws(source)
        node = make_node('unsupported', 'AWS', 'arn:aws', condition_json=source)
        populate_condition_cel(node)
        self.assertIsNone(node['condition_cel'])
        self.assertIn('CEL conversion unavailable', node['comment'])
        self.assertEqual(node['condition_json'], source)
        self.assertFalse(run(populate_condition_cel(make_node('empty', 'AWS', 'arn:aws', 'OR'))['condition_cel']))
