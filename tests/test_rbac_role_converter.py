#    Copyright 2017 AT&T Inc.
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

import os

from tempest import config
from tempest.tests import base

from patrole_tempest_plugin import rbac_role_converter

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

    def test_custom_policy(self):
        default_roles = ['zero', 'one', 'two', 'three', 'four',
                         'five', 'six', 'seven', 'eight', 'nine']

        converter = rbac_role_converter.RbacPolicyConverter(
            None, "test", self.custom_policy_file)

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
            self.assertRaises(KeyError, converter.allowed, fake_rule, role)

        for rule, role_list in expected.items():
            for role in role_list:
                self.assertTrue(converter.allowed(rule, role))
            for role in set(default_roles) - set(role_list):
                self.assertFalse(converter.allowed(rule, role))

    def test_admin_policy_file_with_admin_role(self):
        converter = rbac_role_converter.RbacPolicyConverter(
            None, "test", self.admin_policy_file)

        role = 'admin'
        allowed_rules = [
            'admin_rule'
        ]
        disallowed_rules = [
            'is_admin_rule', 'alt_admin_rule', 'non_admin_rule']

        for rule in allowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertTrue(allowed)

        for rule in disallowed_rules:
            allowed = converter.allowed(rule, role)
            self.assertFalse(allowed)

    def test_admin_policy_file_with_member_role(self):
        converter = rbac_role_converter.RbacPolicyConverter(
            None, "test", self.admin_policy_file)

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
