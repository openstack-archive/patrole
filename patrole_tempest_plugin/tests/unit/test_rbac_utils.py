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

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils

CONF = config.CONF


class RBACUtilsTest(base.TestCase):

    @mock.patch.object(rbac_utils, 'time', autospec=True)
    def setUp(self, _):
        super(RBACUtilsTest, self).setUp()
        self.mock_creds_provider = mock.patch.object(
            rbac_utils, 'credentials_factory', autospec=True).start()

        available_roles = {
            'roles': [
                {'name': 'admin', 'id': 'admin_id'},
                {'name': 'Member', 'id': 'member_id'}
            ]
        }
        self.mock_creds_provider.get_credentials_provider.return_value.\
            creds_client.roles_client.list_roles.return_value = \
            available_roles
        self.addCleanup(mock.patch.stopall)

        CONF.set_override('rbac_test_role', 'Member', group='rbac',
                          enforce_type=True)
        self.addCleanup(CONF.clear_override, 'rbac_test_role', group='rbac')

        # Because rbac_utils is a singleton, reset all of its role-related
        # parameters to the correct values for each test run.
        self.rbac_utils = rbac_utils.rbac_utils()
        self.rbac_utils.available_roles = available_roles
        self.rbac_utils.admin_role_id = 'admin_id'
        self.rbac_utils.rbac_role_id = 'member_id'

    def test_initialization_with_missing_admin_role(self):
        self.rbac_utils.admin_role_id = None
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, None)
        self.assertIn("Defined 'rbac_role' or 'admin' role does not exist"
                      " in the system.", e.__str__())

    def test_initialization_with_missing_rbac_role(self):
        self.rbac_utils.rbac_role_id = None
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, None)
        self.assertIn("Defined 'rbac_role' or 'admin' role does not exist"
                      " in the system.", e.__str__())

    def test_clear_user_roles(self):
        self.rbac_utils.creds_client = mock.Mock()
        creds_client = self.rbac_utils.creds_client
        creds_client.roles_client.list_user_roles_on_project.return_value = {
            'roles': [{'id': 'admin_id'}, {'id': 'member_id'}]
        }

        self.rbac_utils._clear_user_roles(mock.sentinel.user_id,
                                          mock.sentinel.project_id)

        creds_client.roles_client.list_user_roles_on_project.\
            assert_called_once_with(mock.sentinel.project_id,
                                    mock.sentinel.user_id)
        creds_client.roles_client.delete_role_from_user_on_project.\
            assert_has_calls([
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'admin_id'),
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'member_id'),
            ])

    @mock.patch.object(rbac_utils.rbac_utils, '_clear_user_roles',
                       autospec=True)
    def test_rbac_utils_switch_role_to_admin(self, mock_clear_user_roles):
        mock_test_object = mock.Mock()
        mock_test_object.auth_provider.credentials.user_id = \
            mock.sentinel.user_id
        mock_test_object.auth_provider.credentials.tenant_id = \
            mock.sentinel.project_id

        self.rbac_utils.creds_client = mock.Mock()
        creds_client = self.rbac_utils.creds_client

        self.rbac_utils.switch_role(mock_test_object, False)

        creds_client.roles_client.create_user_role_on_project.\
            assert_called_once_with(mock.sentinel.project_id,
                                    mock.sentinel.user_id,
                                    'admin_id')
        mock_clear_user_roles.assert_called_once_with(
            self.rbac_utils, mock.sentinel.user_id, mock.sentinel.project_id)
        mock_test_object.auth_provider.clear_auth.assert_called_once_with()
        mock_test_object.auth_provider.set_auth.assert_called_once_with()

    @mock.patch.object(rbac_utils.rbac_utils, '_clear_user_roles',
                       autospec=True)
    def test_rbac_utils_switch_role_to_rbac_role(self, mock_clear_user_roles):
        mock_test_object = mock.Mock()
        mock_test_object.auth_provider.credentials.user_id = \
            mock.sentinel.user_id
        mock_test_object.auth_provider.credentials.tenant_id = \
            mock.sentinel.project_id

        self.rbac_utils.creds_client = mock.Mock()
        creds_client = self.rbac_utils.creds_client

        self.rbac_utils.switch_role(mock_test_object, True)

        creds_client.roles_client.create_user_role_on_project.\
            assert_called_once_with(mock.sentinel.project_id,
                                    mock.sentinel.user_id,
                                    'member_id')
        mock_clear_user_roles.assert_called_once_with(
            self.rbac_utils, mock.sentinel.user_id, mock.sentinel.project_id)
        mock_test_object.auth_provider.clear_auth.assert_called_once_with()
        mock_test_object.auth_provider.set_auth.assert_called_once_with()

    def test_rbac_utils_switch_roles_with_invalid_value(self):
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, None)
        self.assertIn("Wrong value for parameter 'switchToRbacRole' is passed."
                      " It should be either 'True' or 'False'.", e.__str__())

    @mock.patch.object(rbac_utils.rbac_utils, '_clear_user_roles',
                       autospec=True)
    def test_rbac_utils_switch_role_except_exception(self,
                                                     mock_clear_user_roles):
        self.rbac_utils.creds_client = mock.Mock()
        creds_client = self.rbac_utils.creds_client
        creds_client.roles_client.create_user_role_on_project.side_effect =\
            lib_exc.NotFound

        self.assertRaises(lib_exc.NotFound, self.rbac_utils.switch_role,
                          mock.Mock(), True)
