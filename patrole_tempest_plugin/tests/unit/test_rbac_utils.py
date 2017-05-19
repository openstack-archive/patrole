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
import testtools

from tempest import config
from tempest.lib import base as lib_base
from tempest.lib import exceptions as lib_exc
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils

CONF = config.CONF


class RBACUtilsTest(base.TestCase):

    available_roles = {
        'roles': [
            {'name': 'admin', 'id': 'admin_id'},
            {'name': 'Member', 'id': 'member_id'}
        ]
    }

    @mock.patch.object(rbac_utils, 'credentials', autospec=True,
                       **{'is_admin_available.return_value': True})
    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    def setUp(self, *args):
        super(RBACUtilsTest, self).setUp()

        self.mock_test_obj = mock.Mock(spec=lib_base.BaseTestCase)
        self.mock_test_obj.auth_provider = mock.Mock(
            **{'credentials.user_id': mock.sentinel.user_id,
               'credentials.tenant_id': mock.sentinel.project_id})
        self.mock_test_obj.os_admin = mock.Mock(
            **{'roles_v3_client.list_roles.return_value': self.available_roles}
        )
        self.mock_test_obj.get_identity_version = mock.Mock(return_value=3)

        with mock.patch.object(rbac_utils.RbacUtils, '_validate_switch_role'):
            self.rbac_utils = rbac_utils.RbacUtils(self.mock_test_obj)
        self.rbac_utils.switch_role_history = {}
        self.rbac_utils.admin_role_id = 'admin_id'
        self.rbac_utils.rbac_role_id = 'member_id'

        CONF.set_override('admin_role', 'admin', group='identity')
        CONF.set_override('auth_version', 'v3', group='identity')
        CONF.set_override('rbac_test_role', 'Member', group='rbac')

        roles_client = self.mock_test_obj.os_admin.roles_v3_client
        roles_client.create_user_role_on_project.reset_mock()
        self.mock_test_obj.auth_provider.reset_mock()

        self.addCleanup(CONF.clear_override, 'rbac_test_role', group='rbac')
        self.addCleanup(CONF.clear_override, 'admin_role', group='identity')
        self.addCleanup(CONF.clear_override, 'auth_version', group='identity')
        self.addCleanup(mock.patch.stopall)

    def _mock_list_user_roles_on_project(self, return_value):
        self.mock_test_obj.admin_manager = mock.Mock(
            **{'roles_client.list_user_roles_on_project.'
               'return_value': {'roles': [{'id': return_value}]}})

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    def test_initialization_with_missing_admin_role(self, _):
        self.mock_test_obj.os_admin = mock.Mock(
            **{'roles_v3_client.list_roles.return_value':
               {'roles': [{'name': 'Member', 'id': 'member_id'}]}})
        self.rbac_utils.admin_role_id = None
        self.rbac_utils.rbac_role_id = None
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, self.mock_test_obj,
                              True)
        self.assertIn("Role with name 'admin' does not exist in the system.",
                      e.__str__())

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    def test_initialization_with_missing_rbac_role(self, _):
        self.mock_test_obj.os_admin = mock.Mock(
            **{'roles_v3_client.list_roles.return_value':
               {'roles': [{'name': 'admin', 'id': 'admin_id'}]}})
        self.rbac_utils.admin_role_id = None
        self.rbac_utils.rbac_role_id = None
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, self.mock_test_obj,
                              True)
        self.assertIn("Role defined by rbac_test_role does not exist in the "
                      "system.", e.__str__())

    def test_clear_user_roles(self):
        roles_client = self.mock_test_obj.os_admin.roles_v3_client
        roles_client.list_user_roles_on_project.return_value = {
            'roles': [{'id': 'admin_id'}, {'id': 'member_id'}]
        }

        self.rbac_utils.roles_client = roles_client
        self.rbac_utils.project_id = mock.sentinel.project_id
        self.rbac_utils.user_id = mock.sentinel.user_id

        self.rbac_utils._clear_user_roles(None)

        roles_client.list_user_roles_on_project.\
            assert_called_once_with(mock.sentinel.project_id,
                                    mock.sentinel.user_id)
        roles_client.delete_role_from_user_on_project.\
            assert_has_calls([
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'admin_id'),
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'member_id'),
            ])

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    @mock.patch.object(rbac_utils, 'time', autospec=True)
    def test_rbac_utils_switch_role_to_admin_role(self, mock_time, _):
        self.rbac_utils.prev_switch_role = True
        self._mock_list_user_roles_on_project('admin_id')
        roles_client = self.mock_test_obj.os_admin.roles_v3_client

        self.rbac_utils.switch_role(self.mock_test_obj, False)

        roles_client.create_user_role_on_project.assert_called_once_with(
            mock.sentinel.project_id, mock.sentinel.user_id, 'admin_id')
        self.mock_test_obj.auth_provider.clear_auth.assert_called_once_with()
        self.mock_test_obj.auth_provider.set_auth.assert_called_once_with()
        mock_time.sleep.assert_called_once_with(1)

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    @mock.patch.object(rbac_utils, 'time', autospec=True)
    def test_rbac_utils_switch_role_to_rbac_role(self, mock_time, _):
        self._mock_list_user_roles_on_project('member_id')
        roles_client = self.mock_test_obj.os_admin.roles_v3_client

        self.rbac_utils.switch_role(self.mock_test_obj, True)

        roles_client.create_user_role_on_project.assert_called_once_with(
            mock.sentinel.project_id, mock.sentinel.user_id, 'member_id')
        self.mock_test_obj.auth_provider.clear_auth.assert_called_once_with()
        self.mock_test_obj.auth_provider.set_auth.assert_called_once_with()
        mock_time.sleep.assert_called_once_with(1)

    def test_RBAC_utils_switch_roles_without_boolean_value(self):
        self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                          self.rbac_utils.switch_role, self.mock_test_obj,
                          "admin")
        self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                          self.rbac_utils.switch_role, self.mock_test_obj,
                          None)

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    def test_rbac_utils_switch_roles_with_false_value_twice(self, _):
        self._mock_list_user_roles_on_project('admin_id')
        self.rbac_utils.switch_role(self.mock_test_obj, False)
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, self.mock_test_obj,
                              False)
        self.assertIn(
            '`toggle_rbac_role` must not be called with the same bool value '
            'twice. Make sure that you included a rbac_utils.switch_role '
            'method call inside the test.', str(e))

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    def test_rbac_utils_switch_roles_with_true_value_twice(self, _):
        self._mock_list_user_roles_on_project('admin_id')
        self.rbac_utils.switch_role(self.mock_test_obj, True)
        e = self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                              self.rbac_utils.switch_role, self.mock_test_obj,
                              True)
        self.assertIn(
            '`toggle_rbac_role` must not be called with the same bool value '
            'twice. Make sure that you included a rbac_utils.switch_role '
            'method call inside the test.', str(e))

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    @mock.patch.object(rbac_utils, 'LOG', autospec=True)
    @mock.patch.object(rbac_utils, 'sys', autospec=True)
    def test_rbac_utils_switch_roles_with_unhandled_exception(self, mock_sys,
                                                              mock_log, _):
        """Test whether throwing an unhandled exception doesn't throw error.

        If a skip exception, say, is thrown then this means that switch_role is
        never called within the test function. But if an unhandled exception
        or skip exception is thrown, then this should not result in an error
        being raised.
        """
        self._mock_list_user_roles_on_project('member_id')

        # Skip exception is an example of a legitimate case where `switch_role`
        # is thrown. AttributeError, on the other hand, is an example of an
        # unexpected exception being thrown that should be allowed to bubble
        # up, rather than being obfuscated by `switch_role` error being thrown
        # instead.
        unhandled_exceptions = [testtools.TestCase.skipException,
                                AttributeError]

        for unhandled_exception in unhandled_exceptions:
            mock_sys.exc_info.return_value = [unhandled_exception]

            # Ordinarily switching to the same role would result in an error,
            # but because the skipException is thrown before the test finishes,
            # this is not treated as a failure.
            self.rbac_utils.switch_role(self.mock_test_obj, False)
            self.rbac_utils.switch_role(self.mock_test_obj, False)
            mock_log.error.assert_not_called()

            self.rbac_utils.switch_role(self.mock_test_obj, True)
            self.rbac_utils.switch_role(self.mock_test_obj, True)
            mock_log.error.assert_not_called()

    @mock.patch.object(rbac_utils.RbacUtils, '_clear_user_roles',
                       autospec=True, return_value=False)
    def test_rbac_utils_switch_role_except_exception(self,
                                                     mock_clear_user_roles):
        roles_client = self.mock_test_obj.os_admin.roles_v3_client
        roles_client.create_user_role_on_project.side_effect =\
            lib_exc.NotFound

        self.assertRaises(lib_exc.NotFound, self.rbac_utils.switch_role,
                          self.mock_test_obj, True)
