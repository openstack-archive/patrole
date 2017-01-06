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
                                               'custom_rbac_policy.json')

    def test_custom_policy(self):
        default_roles = ['zero', 'one', 'two', 'three', 'four',
                         'five', 'six', 'seven', 'eight', 'nine']
        CONF.set_override('rbac_roles', default_roles, group='rbac',
                          enforce_type=True)

        self.converter = rbac_role_converter.RbacPolicyConverter(
            "custom",
            self.custom_policy_file
        )
        self.roles_dict = self.converter.rules

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

        self.assertFalse(fake_rule in self.roles_dict.keys())

        for rule in expected.keys():
            self.assertTrue(rule in self.roles_dict.keys())
            expected_roles = expected[rule]
            unexpected_roles = set(default_roles) - set(expected[rule])
            for role in expected_roles:
                self.assertTrue(role in self.roles_dict[rule])
            for role in unexpected_roles:
                self.assertFalse(role in self.roles_dict[rule])
