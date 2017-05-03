# Copyright 2017 AT&T Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import mock
import os

from tempest import config
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_policy_parser

CONF = config.CONF


class RbacPolicyTest(base.TestCase):

    def setUp(self):
        super(RbacPolicyTest, self).setUp()
        self.mock_admin_mgr = mock.patch.object(
            rbac_policy_parser, 'credentials').start()
        self.mock_path = mock.patch.object(
            rbac_policy_parser, 'os').start()

        current_directory = os.path.dirname(os.path.realpath(__file__))
        self.custom_policy_file = os.path.join(current_directory,
                                               'resources',
                                               'custom_rbac_policy.json')
        self.admin_policy_file = os.path.join(current_directory,
                                              'resources',
                                              'admin_rbac_policy.json')
        self.alt_admin_policy_file = os.path.join(current_directory,
                                                  'resources',
                                                  'alt_admin_rbac_policy.json')
        self.tenant_policy_file = os.path.join(current_directory,
                                               'resources',
                                               'tenant_rbac_policy.json')
        services = {
            'services': [
                {'name': 'cinder', 'links': 'link', 'enabled': True,
                 'type': 'volume', 'id': 'id',
                 'description': 'description'},
                {'name': 'glance', 'links': 'link', 'enabled': True,
                 'type': 'image', 'id': 'id',
                 'description': 'description'},
                {'name': 'nova', 'links': 'link', 'enabled': True,
                 'type': 'compute', 'id': 'id',
                 'description': 'description'},
                {'name': 'keystone', 'links': 'link', 'enabled': True,
                 'type': 'identity', 'id': 'id',
                 'description': 'description'},
                {'name': 'heat', 'links': 'link', 'enabled': True,
                 'type': 'orchestration', 'id': 'id',
                 'description': 'description'},
                {'name': 'neutron', 'links': 'link', 'enabled': True,
                 'type': 'networking', 'id': 'id',
                 'description': 'description'},
                {'name': 'test', 'links': 'link', 'enabled': True,
                 'type': 'unit_test', 'id': 'id',
                 'description': 'description'}
            ]
        }

        self.mock_admin_mgr.AdminManager.return_value.\
            identity_services_v3_client.list_services.return_value = \
            services

    def _get_fake_policy_rule(self, name, rule):
        fake_rule = mock.Mock(check=rule)
        fake_rule.name = name
        return fake_rule

    @mock.patch.object(rbac_policy_parser, 'LOG', autospec=True)
    def test_custom_policy(self, m_log):
        default_roles = ['zero', 'one', 'two', 'three', 'four',
                         'five', 'six', 'seven', 'eight', 'nine']

        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.custom_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        expected = {
            'policy_action_1': ['two', 'four', 'six', 'eight'],
            'policy_action_2': ['one', 'three', 'five', 'seven', 'nine'],
            'policy_action_3': ['zero'],
            'policy_action_4': ['one', 'two', 'three', 'five', 'seven'],
            'policy_action_5': ['zero', 'one', 'two', 'three', 'four', 'five',
                                'six', 'seven', 'eight', 'nine'],
            'policy_action_6': ['eight'],
        }

        for rule, role_list in expected.items():
            for role in role_list:
                self.assertTrue(parser.allowed(rule, role))
            for role in set(default_roles) - set(role_list):
                self.assertFalse(parser.allowed(rule, role))

    def test_admin_policy_file_with_admin_role(self):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.admin_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        role = 'admin'
        allowed_rules = [
            'admin_rule', 'is_admin_rule', 'alt_admin_rule'
        ]
        disallowed_rules = ['non_admin_rule']

        for rule in allowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertFalse(allowed)

    def test_admin_policy_file_with_member_role(self):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.admin_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        role = 'Member'
        allowed_rules = [
            'non_admin_rule'
        ]
        disallowed_rules = [
            'admin_rule', 'is_admin_rule', 'alt_admin_rule']

        for rule in allowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertFalse(allowed)

    def test_admin_policy_file_with_context_is_admin(self):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.alt_admin_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        role = 'fake_admin'
        allowed_rules = ['non_admin_rule']
        disallowed_rules = ['admin_rule']

        for rule in allowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertFalse(allowed)

        role = 'super_admin'
        allowed_rules = ['admin_rule']
        disallowed_rules = ['non_admin_rule']

        for rule in allowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = parser.allowed(rule, role)
            self.assertFalse(allowed)

    def test_tenant_user_policy(self):
        """Test whether rules with format tenant_id/user_id formatting work.

        Test whether Neutron rules that contain project_id, tenant_id, and
        network:tenant_id pass. And test whether Nova rules that contain
        user_id pass.
        """
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.tenant_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        # Check whether Member role can perform expected actions.
        allowed_rules = ['rule1', 'rule2', 'rule3', 'rule4']
        for rule in allowed_rules:
            allowed = parser.allowed(rule, 'Member')
            self.assertTrue(allowed)

        disallowed_rules = ['admin_tenant_rule', 'admin_user_rule']
        for disallowed_rule in disallowed_rules:
            self.assertFalse(parser.allowed(disallowed_rule, 'Member'))

        # Check whether admin role can perform expected actions.
        allowed_rules.extend(disallowed_rules)
        for rule in allowed_rules:
            allowed = parser.allowed(rule, 'admin')
            self.assertTrue(allowed)

        # Check whether _try_rule is called with the correct target dictionary.
        with mock.patch.object(
            parser, '_try_rule', return_value=True, autospec=True) \
            as mock_try_rule:

            expected_target = {
                "project_id": mock.sentinel.tenant_id,
                "tenant_id": mock.sentinel.tenant_id,
                "network:tenant_id": mock.sentinel.tenant_id,
                "user_id": mock.sentinel.user_id
            }

            expected_access_data = {
                "roles": ['Member'],
                "is_admin": False,
                "is_admin_project": True,
                "user_id": mock.sentinel.user_id,
                "tenant_id": mock.sentinel.tenant_id,
                "project_id": mock.sentinel.tenant_id
            }

            for rule in allowed_rules:
                allowed = parser.allowed(rule, 'Member')
                self.assertTrue(allowed)
                mock_try_rule.assert_called_once_with(
                    rule, expected_target, expected_access_data, mock.ANY)
                mock_try_rule.reset_mock()

    @mock.patch.object(rbac_policy_parser, 'LOG', autospec=True)
    def test_invalid_service_raises_exception(self, m_log):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        service = 'invalid_service'

        self.assertRaises(rbac_exceptions.RbacInvalidService,
                          rbac_policy_parser.RbacPolicyParser,
                          test_tenant_id,
                          test_user_id,
                          service)

        m_log.debug.assert_called_once_with(
            "{0} is NOT a valid service.".format(str(service)))

    @mock.patch.object(rbac_policy_parser, 'LOG', autospec=True)
    def test_service_is_none_raises_exception(self, m_log):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        service = None

        self.assertRaises(rbac_exceptions.RbacInvalidService,
                          rbac_policy_parser.RbacPolicyParser,
                          test_tenant_id,
                          test_user_id,
                          service)

        m_log.debug.assert_called_once_with(
            "{0} is NOT a valid service.".format(str(service)))

    @mock.patch.object(rbac_policy_parser, 'LOG', autospec=True)
    def test_invalid_policy_rule_throws_rbac_parsing_exception(self, m_log):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.custom_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        fake_rule = 'fake_rule'
        expected_message = "Policy action: {0} not found in policy file: {1}."\
                           .format(fake_rule, self.custom_policy_file)

        e = self.assertRaises(rbac_exceptions.RbacParsingException,
                              parser.allowed, fake_rule, None)
        self.assertIn(expected_message, str(e))
        m_log.debug.assert_called_once_with(expected_message)

    @mock.patch.object(rbac_policy_parser, 'LOG', autospec=True)
    def test_unknown_exception_throws_rbac_parsing_exception(self, m_log):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.custom_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")
        parser.rules = mock.MagicMock(
            **{'__getitem__.return_value.side_effect': Exception(
               mock.sentinel.error)})

        expected_message = "Policy action: {0} not found in "\
                           "policy file: {1}.".format(mock.sentinel.rule,
                                                      self.custom_policy_file)

        e = self.assertRaises(rbac_exceptions.RbacParsingException,
                              parser.allowed, mock.sentinel.rule, None)
        self.assertIn(expected_message, str(e))
        m_log.debug.assert_called_once_with(expected_message)

    @mock.patch.object(rbac_policy_parser, 'stevedore', autospec=True)
    def test_get_policy_data_from_file_and_from_code(self, mock_stevedore):
        fake_policy_rules = [
            self._get_fake_policy_rule('code_policy_action_1',
                                       'rule:code_rule_1'),
            self._get_fake_policy_rule('code_policy_action_2',
                                       'rule:code_rule_2'),
            self._get_fake_policy_rule('code_policy_action_3',
                                       'rule:code_rule_3'),
        ]

        mock_manager = mock.Mock(obj=fake_policy_rules)
        mock_manager.configure_mock(name='fake_service')
        mock_stevedore.named.NamedExtensionManager.return_value = [
            mock_manager
        ]

        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.tenant_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        policy_data = parser._get_policy_data('fake_service')

        self.assertIsInstance(policy_data, str)

        actual_policy_data = json.loads(policy_data)
        expected_policy_data = {
            "code_policy_action_1": "rule:code_rule_1",
            "code_policy_action_2": "rule:code_rule_2",
            "code_policy_action_3": "rule:code_rule_3",
            "rule1": "tenant_id:%(network:tenant_id)s",
            "rule2": "tenant_id:%(tenant_id)s",
            "rule3": "project_id:%(project_id)s",
            "rule4": "user_id:%(user_id)s",
            "admin_tenant_rule": "role:admin and tenant_id:%(tenant_id)s",
            "admin_user_rule": "role:admin and user_id:%(user_id)s"

        }

        self.assertEqual(expected_policy_data, actual_policy_data)

    @mock.patch.object(rbac_policy_parser, 'stevedore', autospec=True)
    def test_get_policy_data_from_file_and_from_code_with_overwrite(
            self, mock_stevedore):
        # The custom policy file should overwrite default rules rule1 and rule2
        # that are defined in code.
        fake_policy_rules = [
            self._get_fake_policy_rule('rule1', 'rule:code_rule_1'),
            self._get_fake_policy_rule('rule2', 'rule:code_rule_2'),
            self._get_fake_policy_rule('code_policy_action_3',
                                       'rule:code_rule_3'),
        ]

        mock_manager = mock.Mock(obj=fake_policy_rules)
        mock_manager.configure_mock(name='fake_service')
        mock_stevedore.named.NamedExtensionManager.return_value = [
            mock_manager
        ]

        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        self.mock_path.path.join.return_value = self.tenant_policy_file
        parser = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test")

        policy_data = parser._get_policy_data('fake_service')

        self.assertIsInstance(policy_data, str)

        actual_policy_data = json.loads(policy_data)
        expected_policy_data = {
            "code_policy_action_3": "rule:code_rule_3",
            "rule1": "tenant_id:%(network:tenant_id)s",
            "rule2": "tenant_id:%(tenant_id)s",
            "rule3": "project_id:%(project_id)s",
            "rule4": "user_id:%(user_id)s",
            "admin_tenant_rule": "role:admin and tenant_id:%(tenant_id)s",
            "admin_user_rule": "role:admin and user_id:%(user_id)s"
        }

        self.assertEqual(expected_policy_data, actual_policy_data)

    @mock.patch.object(rbac_policy_parser, 'credentials', autospec=True)
    @mock.patch.object(rbac_policy_parser, 'stevedore', autospec=True)
    def test_get_policy_data_cannot_find_policy(self, mock_stevedore,
                                                mock_creds):
        mock_stevedore.named.NamedExtensionManager.return_value = None
        mock_creds.AdminManager.return_value.identity_services_v3_client.\
            list_services.return_value = {
                'services': [{'name': 'test_service'}]}
        self.mock_path.path.join.return_value = '/etc/test_service/policy.json'
        e = self.assertRaises(rbac_exceptions.RbacParsingException,
                              rbac_policy_parser.RbacPolicyParser,
                              None, None, 'test_service')

        expected_error = \
            'Policy file for {0} service neither found in code '\
            'nor at {1}.'.format('test_service',
                                 '/etc/test_service/policy.json')

        self.assertIn(expected_error, str(e))

    @mock.patch.object(rbac_policy_parser, 'json', autospec=True)
    @mock.patch.object(rbac_policy_parser, 'credentials', autospec=True)
    @mock.patch.object(rbac_policy_parser, 'stevedore', autospec=True)
    def test_get_policy_data_without_valid_policy(self, mock_stevedore,
                                                  mock_credentials, mock_json):
        self.mock_path.path.isfile.return_value = False

        test_policy_action = mock.Mock(check='rule:bar')
        test_policy_action.configure_mock(name='foo')

        test_policy = mock.Mock(obj=[test_policy_action])
        test_policy.configure_mock(name='test_service')

        mock_stevedore.named.NamedExtensionManager\
            .return_value = [test_policy]

        mock_credentials.AdminManager.return_value.identity_services_v3_client.\
            list_services.return_value = {
                'services': [{'name': 'test_service'}]
            }

        mock_json.dumps.side_effect = ValueError

        e = self.assertRaises(rbac_exceptions.RbacParsingException,
                              rbac_policy_parser.RbacPolicyParser,
                              None, None, 'test_service')

        expected_error = "Policy file for {0} service is invalid."\
                         .format("test_service")

        self.assertIn(expected_error, str(e))

        mock_stevedore.named.NamedExtensionManager.assert_called_once_with(
            'oslo.policy.policies',
            names=['test_service'],
            on_load_failure_callback=None,
            invoke_on_load=True,
            warn_on_missing_entrypoint=False)

    @mock.patch.object(rbac_policy_parser, 'json', autospec=True)
    @mock.patch.object(rbac_policy_parser, 'credentials', autospec=True)
    @mock.patch.object(rbac_policy_parser, 'stevedore', autospec=True)
    def test_get_policy_data_from_file_not_json(self, mock_stevedore,
                                                mock_credentials,
                                                mock_json):

        mock_credentials.AdminManager.return_value.identity_services_v3_client.\
            list_services.return_value = {
                'services': [{'name': 'test_service'}]
            }
        mock_stevedore.named.NamedExtensionManager.return_value = None
        mock_json.loads.side_effect = ValueError
        self.mock_path.path.join.return_value = self.tenant_policy_file
        e = self.assertRaises(rbac_exceptions.RbacParsingException,
                              rbac_policy_parser.RbacPolicyParser,
                              None, None, 'test_service')

        expected_error = 'Policy file for {0} service neither found in code '\
                         'nor at {1}.'.format('test_service',
                                              self.tenant_policy_file)

        self.assertIn(expected_error, str(e))
