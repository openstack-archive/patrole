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

from tempest.lib import exceptions as lib_exc
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils


class RBACUtilsTest(base.TestCase):
    def setUp(self):
        super(RBACUtilsTest, self).setUp()
        mock_creds_provider = mock.patch.object(
            rbac_utils, 'credentials_factory').start()
        mock_creds_provider.get_credentials_provider.return_value.\
            creds_client.roles_client.list_roles.return_value.\
            __getitem__.return_value = [
                {'name': 'admin', 'id': 'admin_id'},
                {'name': 'Member', 'id': 'member_id'}
            ]
        self.rbac_utils = rbac_utils.rbac_utils()

    def test_rbac_utils_switch_roles_none(self):
        self.assertRaises(rbac_exceptions.RbacActionFailed,
                          self.rbac_utils.switch_role, None)

    def test_rbac_utils_switch_roles_false(self):
        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"
        self.assertIsNone(self.rbac_utils.switch_role(self, False))

    def test_rbac_utils_switch_roles_get_roles_fails(self):
        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"
        self.rbac_utils.creds_client.roles_client.create_user_role_on_project.\
            side_effect = lib_exc.NotFound
        self.assertRaises(lib_exc.NotFound, self.rbac_utils.switch_role, self,
                          False)
