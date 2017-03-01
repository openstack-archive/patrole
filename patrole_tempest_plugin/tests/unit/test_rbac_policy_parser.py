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

import mock
import os

from tempest import config
from tempest.tests import base

from patrole_tempest_plugin import rbac_policy_parser

CONF = config.CONF


class RbacPolicyTest(base.TestCase):

    def setUp(self):
        super(RbacPolicyTest, self).setUp()

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

    @mock.patch.object(rbac_policy_parser, 'LOG', autospec=True)
    def test_custom_policy(self, m_log):
        default_roles = ['zero', 'one', 'two', 'three', 'four',
                         'five', 'six', 'seven', 'eight', 'nine']

        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        converter = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test", self.custom_policy_file)

        expected = {
            'policy_action_1': ['two', 'four', 'six', 'eight'],
            'policy_action_2': ['one', 'three', 'five', 'seven', 'nine'],
            'policy_action_3': ['zero'],
            'policy_action_4': ['one', 'two', 'three', 'five', 'seven'],
            'policy_action_5': ['zero', 'one', 'two', 'three', 'four', 'five',
                                'six', 'seven', 'eight', 'nine'],
            'policy_action_6': ['eight'],
        }

        fake_rule = 'fake_rule'

        for role in default_roles:
            self.assertFalse(converter.allowed(fake_rule, role))
            m_log.debug.assert_called_once_with(
                "{0} not found in policy file.".format('fake_rule'))
            m_log.debug.reset_mock()

        for rule, role_list in expected.items():
            for role in role_list:
                self.assertTrue(converter.allowed(rule, role))
            for role in set(default_roles) - set(role_list):
                self.assertFalse(converter.allowed(rule, role))

    def test_admin_policy_file_with_admin_role(self):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        converter = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test", self.admin_policy_file)

        role = 'admin'
        allowed_rules = [
            'admin_rule', 'is_admin_rule', 'alt_admin_rule'
        ]
        disallowed_rules = ['non_admin_rule']

        for rule in allowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertFalse(allowed)

    def test_admin_policy_file_with_member_role(self):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        converter = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test", self.admin_policy_file)

        role = 'Member'
        allowed_rules = [
            'non_admin_rule'
        ]
        disallowed_rules = [
            'admin_rule', 'is_admin_rule', 'alt_admin_rule']

        for rule in allowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertFalse(allowed)

    def test_admin_policy_file_with_context_is_admin(self):
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        converter = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test", self.alt_admin_policy_file)

        role = 'fake_admin'
        allowed_rules = ['non_admin_rule']
        disallowed_rules = ['admin_rule']

        for rule in allowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertFalse(allowed)

        role = 'super_admin'
        allowed_rules = ['admin_rule']
        disallowed_rules = ['non_admin_rule']

        for rule in allowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertFalse(allowed)

    def test_tenant_user_policy(self):
        """Test whether rules with format tenant_id/user_id formatting work.

        Test whether Neutron rules that contain project_id, tenant_id, and
        network:tenant_id pass. And test whether Nova rules that contain
        user_id pass.
        """
        test_tenant_id = mock.sentinel.tenant_id
        test_user_id = mock.sentinel.user_id
        converter = rbac_policy_parser.RbacPolicyParser(
            test_tenant_id, test_user_id, "test", self.tenant_policy_file)

        # Check whether Member role can perform expected actions.
        allowed_rules = ['rule1', 'rule2', 'rule3', 'rule4']
        for rule in allowed_rules:
            allowed = converter.allowed(rule, 'Member')
            self.assertTrue(allowed)

        disallowed_rules = ['admin_tenant_rule', 'admin_user_rule']
        for disallowed_rule in disallowed_rules:
            self.assertFalse(converter.allowed(disallowed_rule, 'Member'))

        # Check whether admin role can perform expected actions.
        allowed_rules.extend(disallowed_rules)
        for rule in allowed_rules:
            allowed = converter.allowed(rule, 'admin')
            self.assertTrue(allowed)

        # Check whether _try_rule is called with the correct target dictionary.
        with mock.patch.object(
            converter, '_try_rule', return_value=True, autospec=True) \
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
                allowed = converter.allowed(rule, 'Member')
                self.assertTrue(allowed)
                mock_try_rule.assert_called_once_with(
                    rule, expected_target, expected_access_data, mock.ANY)
                mock_try_rule.reset_mock()
