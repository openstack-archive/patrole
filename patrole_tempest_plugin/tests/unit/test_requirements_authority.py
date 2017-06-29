# Copyright 2017 AT&T Corporation.
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

from tempest.lib import exceptions
from tempest.tests import base

from patrole_tempest_plugin import requirements_authority as req_auth


class RequirementsAuthorityTest(base.TestCase):
    def setUp(self):
        super(RequirementsAuthorityTest, self).setUp()
        self.rbac_auth = req_auth.RequirementsAuthority()
        self.current_directory = os.path.dirname(os.path.realpath(__file__))
        self.yaml_test_file = os.path.join(self.current_directory,
                                           'resources',
                                           'rbac_roles.yaml')
        self.expected_result = {'test:create': ['test_member', '_member_'],
                                'test:create2': ['test_member']}

    def test_requirements_auth_init(self):
        rbac_auth = req_auth.RequirementsAuthority(self.yaml_test_file, 'Test')
        self.assertEqual(self.expected_result, rbac_auth.roles_dict)

    def test_auth_allowed_empty_roles(self):
        self.rbac_auth.roles_dict = None
        self.assertRaises(exceptions.InvalidConfiguration,
                          self.rbac_auth.allowed, "", "")

    def test_auth_allowed_role_in_api(self):
        self.rbac_auth.roles_dict = {'api': ['_member_']}
        self.assertTrue(self.rbac_auth.allowed("api", "_member_"))

    def test_auth_allowed_role_not_in_api(self):
        self.rbac_auth.roles_dict = {'api': ['_member_']}
        self.assertFalse(self.rbac_auth.allowed("api", "support_member"))

    def test_parser_get_allowed_except_keyerror(self):
        self.rbac_auth.roles_dict = {}
        self.assertRaises(KeyError, self.rbac_auth.allowed,
                          "api", "support_member")

    def test_parser_init(self):
        req_auth.RequirementsParser(self.yaml_test_file)
        self.assertEqual([{'Test': self.expected_result}],
                         req_auth.RequirementsParser.Inner._rbac_map)

    def test_parser_role_in_api(self):
        req_auth.RequirementsParser.Inner._rbac_map = \
            [{'Test': self.expected_result}]
        self.rbac_auth.roles_dict = req_auth.RequirementsParser.parse("Test")

        self.assertEqual(self.expected_result, self.rbac_auth.roles_dict)
        self.assertTrue(self.rbac_auth.allowed("test:create2", "test_member"))

    def test_parser_role_not_in_api(self):
        req_auth.RequirementsParser.Inner._rbac_map = \
            [{'Test': self.expected_result}]
        self.rbac_auth.roles_dict = req_auth.RequirementsParser.parse("Test")

        self.assertEqual(self.expected_result, self.rbac_auth.roles_dict)
        self.assertFalse(self.rbac_auth.allowed("test:create2", "_member_"))

    def test_parser_except_invalid_configuration(self):
        req_auth.RequirementsParser.Inner._rbac_map = \
            [{'Test': self.expected_result}]
        self.rbac_auth.roles_dict = \
            req_auth.RequirementsParser.parse("Failure")

        self.assertIsNone(self.rbac_auth.roles_dict)
        self.assertRaises(exceptions.InvalidConfiguration,
                          self.rbac_auth.allowed, "", "")
