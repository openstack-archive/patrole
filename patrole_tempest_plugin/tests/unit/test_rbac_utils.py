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

from tempest.lib import exceptions as lib_exc
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils
from patrole_tempest_plugin.tests.unit import fixtures as patrole_fixtures


class RBACUtilsTest(base.TestCase):

    def setUp(self):
        super(RBACUtilsTest, self).setUp()
        # Reset the role history after each test run to avoid validation
        # errors between tests.
        rbac_utils.RbacUtils.override_role_history = {}
        self.rbac_utils = self.useFixture(patrole_fixtures.RbacUtilsFixture())

    def test_override_role_with_missing_admin_role(self):
        self.rbac_utils.set_roles('member')
        error_re = (
            'Roles defined by `\[patrole\] rbac_test_role` and `\[identity\] '
            'admin_role` must be defined in the system.')
        self.assertRaisesRegex(rbac_exceptions.RbacResourceSetupFailed,
                               error_re, self.rbac_utils.override_role)

    def test_override_role_with_missing_rbac_role(self):
        self.rbac_utils.set_roles('admin')
        error_re = (
            'Roles defined by `\[patrole\] rbac_test_role` and `\[identity\] '
            'admin_role` must be defined in the system.')
        self.assertRaisesRegex(rbac_exceptions.RbacResourceSetupFailed,
                               error_re, self.rbac_utils.override_role)

    def test_override_role_to_admin_role(self):
        self.rbac_utils.override_role()

        mock_test_obj = self.rbac_utils.mock_test_obj
        roles_client = self.rbac_utils.roles_v3_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_called_once_with(
            self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID, 'admin_id')
        mock_test_obj.os_primary.auth_provider.clear_auth\
            .assert_called_once_with()
        mock_test_obj.os_primary.auth_provider.set_auth\
            .assert_called_once_with()
        mock_time.sleep.assert_called_once_with(1)

    def test_override_role_to_admin_role_avoids_role_switch(self):
        self.rbac_utils.set_roles(['admin', 'member'], 'admin')
        self.rbac_utils.override_role()

        roles_client = self.rbac_utils.roles_v3_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_not_called()
        mock_time.sleep.assert_not_called()

    def test_override_role_to_member_role(self):
        self.rbac_utils.override_role(True)

        mock_test_obj = self.rbac_utils.mock_test_obj
        roles_client = self.rbac_utils.roles_v3_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id'),
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'member_id')
        ])
        mock_test_obj.os_primary.auth_provider.clear_auth.assert_has_calls(
            [mock.call()] * 2)
        mock_test_obj.os_primary.auth_provider.set_auth.assert_has_calls(
            [mock.call()] * 2)
        mock_time.sleep.assert_has_calls([mock.call(1)] * 2)

    def test_override_role_to_member_role_avoids_role_switch(self):
        self.rbac_utils.set_roles(['admin', 'member'], 'member')
        self.rbac_utils.override_role(True)

        roles_client = self.rbac_utils.roles_v3_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id')
        ])
        mock_time.sleep.assert_called_once_with(1)

    def test_override_role_to_member_role_then_admin_role(self):
        self.rbac_utils.override_role(True, False)

        mock_test_obj = self.rbac_utils.mock_test_obj
        roles_client = self.rbac_utils.roles_v3_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id'),
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'member_id'),
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id')
        ])
        mock_test_obj.os_primary.auth_provider.clear_auth.assert_has_calls(
            [mock.call()] * 3)
        mock_test_obj.os_primary.auth_provider.set_auth.assert_has_calls(
            [mock.call()] * 3)
        mock_time.sleep.assert_has_calls([mock.call(1)] * 3)

    def test_clear_user_roles(self):
        # NOTE(felipemonteiro): Set the user's roles on the project to
        # include 'random' to coerce a role switch, or else it will be
        # skipped.
        self.rbac_utils.set_roles(['admin', 'member'], ['member', 'random'])
        self.rbac_utils.override_role()

        roles_client = self.rbac_utils.roles_v3_client

        roles_client.list_user_roles_on_project.assert_called_once_with(
            self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID)
        roles_client.delete_role_from_user_on_project.\
            assert_has_calls([
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'member_id'),
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'random_id')])

    @mock.patch.object(rbac_utils.RbacUtils, '_override_role', autospec=True)
    def test_override_role_context_manager_simulate_pass(self,
                                                         mock_override_role):
        """Validate that expected override_role calls are made when switching
        to admin role for success path.
        """
        test_obj = mock.MagicMock()
        _rbac_utils = rbac_utils.RbacUtils(test_obj)

        # Validate constructor called _override_role with False.
        mock_override_role.assert_called_once_with(_rbac_utils, test_obj,
                                                   False)
        mock_override_role.reset_mock()

        with _rbac_utils.override_role(test_obj):
            # Validate `override_role` public method called private method
            # `_override_role` with True.
            mock_override_role.assert_called_once_with(_rbac_utils, test_obj,
                                                       True)
            mock_override_role.reset_mock()
        # Validate that `override_role` switched back to admin role after
        # contextmanager.
        mock_override_role.assert_called_once_with(_rbac_utils, test_obj,
                                                   False)

    @mock.patch.object(rbac_utils.RbacUtils, '_override_role', autospec=True)
    def test_override_role_context_manager_simulate_fail(self,
                                                         mock_override_role):
        """Validate that expected override_role calls are made when switching
        to admin role for failure path (i.e. when test raises exception).
        """
        test_obj = mock.MagicMock()
        _rbac_utils = rbac_utils.RbacUtils(test_obj)

        # Validate constructor called _override_role with False.
        mock_override_role.assert_called_once_with(_rbac_utils, test_obj,
                                                   False)
        mock_override_role.reset_mock()

        def _do_test():
            with _rbac_utils.override_role(test_obj):
                # Validate `override_role` public method called private method
                # `_override_role` with True.
                mock_override_role.assert_called_once_with(
                    _rbac_utils, test_obj, True)
                mock_override_role.reset_mock()
                # Raise exc to verify role switch works for negative case.
                raise lib_exc.Forbidden()

        # Validate that role is switched back to admin, despite test failure.
        with testtools.ExpectedException(lib_exc.Forbidden):
            _do_test()
        mock_override_role.assert_called_once_with(_rbac_utils, test_obj,
                                                   False)
