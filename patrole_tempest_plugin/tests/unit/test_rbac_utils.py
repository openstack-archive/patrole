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

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils
from patrole_tempest_plugin.tests.unit import base
from patrole_tempest_plugin.tests.unit import fixtures as patrole_fixtures


class RBACUtilsMixinTest(base.TestCase):

    def setUp(self):
        super(RBACUtilsMixinTest, self).setUp()
        self.rbac_utils_fixture = self.useFixture(
            patrole_fixtures.RbacUtilsMixinFixture())
        self.test_obj = self.rbac_utils_fixture.test_obj

    def test_init_roles_with_missing_admin_role(self):
        self.rbac_utils_fixture.set_roles('member')
        error_re = (".*Following roles were not found: admin. Available "
                    "roles: member.")
        self.assertRaisesRegex(rbac_exceptions.RbacResourceSetupFailed,
                               error_re, self.test_obj._init_roles)

    def test_init_roles_with_missing_rbac_role(self):
        self.rbac_utils_fixture.set_roles('admin')
        error_re = (".*Following roles were not found: member. Available "
                    "roles: admin.")
        self.assertRaisesRegex(rbac_exceptions.RbacResourceSetupFailed,
                               error_re, self.test_obj._init_roles)

    def test_override_role_to_admin_role_at_creating(self):
        rbac_utils_fixture = self.useFixture(
            patrole_fixtures.RbacUtilsMixinFixture(do_reset_mocks=False))
        test_obj = rbac_utils_fixture.test_obj
        roles_client = rbac_utils_fixture.admin_roles_client
        mock_time = rbac_utils_fixture.mock_time

        roles_client.create_user_role_on_project.assert_called_once_with(
            rbac_utils_fixture.PROJECT_ID,
            rbac_utils_fixture.USER_ID,
            'admin_id')
        test_obj.get_auth_providers()[0].clear_auth.assert_called_once_with()
        test_obj.get_auth_providers()[0].set_auth.assert_called_once_with()
        mock_time.sleep.assert_called_once_with(1)

    def test_override_role_to_admin_role(self):
        self.test_obj._override_role()

        roles_client = self.rbac_utils_fixture.admin_roles_client
        mock_time = self.rbac_utils_fixture.mock_time

        roles_client.create_user_role_on_project.assert_called_once_with(
            self.rbac_utils_fixture.PROJECT_ID,
            self.rbac_utils_fixture.USER_ID,
            'admin_id')
        self.test_obj.get_auth_providers()[0].clear_auth\
            .assert_called_once_with()
        self.test_obj.get_auth_providers()[0].set_auth\
            .assert_called_once_with()
        mock_time.sleep.assert_called_once_with(1)

    def test_override_role_to_admin_role_avoids_role_switch(self):
        self.rbac_utils_fixture.set_roles(['admin', 'member'], 'admin')
        self.test_obj._override_role()

        roles_client = self.rbac_utils_fixture.admin_roles_client
        mock_time = self.rbac_utils_fixture.mock_time

        roles_client.create_user_role_on_project.assert_not_called()
        mock_time.sleep.assert_not_called()

    def test_override_role_to_member_role(self):
        self.test_obj._override_role(True)

        roles_client = self.rbac_utils_fixture.admin_roles_client
        mock_time = self.rbac_utils_fixture.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils_fixture.PROJECT_ID,
                      self.rbac_utils_fixture.USER_ID,
                      'member_id')
        ])
        self.test_obj.get_auth_providers()[0].clear_auth.assert_has_calls(
            [mock.call()])
        self.test_obj.get_auth_providers()[0].set_auth.assert_has_calls(
            [mock.call()])
        mock_time.sleep.assert_has_calls([mock.call(1)])

    def test_override_role_to_member_role_avoids_role_switch(self):
        self.rbac_utils_fixture.set_roles(['admin', 'member'], 'member')
        self.test_obj._override_role(True)

        roles_client = self.rbac_utils_fixture.admin_roles_client
        mock_time = self.rbac_utils_fixture.mock_time

        self.assertEqual(0,
                         roles_client.create_user_role_on_project.call_count)
        self.assertEqual(0,
                         mock_time.sleep.call_count)

    def test_override_role_to_member_role_then_admin_role(self):
        self.test_obj._override_role(True)
        self.test_obj._override_role(False)

        roles_client = self.rbac_utils_fixture.admin_roles_client
        mock_time = self.rbac_utils_fixture.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils_fixture.PROJECT_ID,
                      self.rbac_utils_fixture.USER_ID,
                      'member_id'),
            mock.call(self.rbac_utils_fixture.PROJECT_ID,
                      self.rbac_utils_fixture.USER_ID,
                      'admin_id')
        ])
        self.test_obj.get_auth_providers()[0].clear_auth.assert_has_calls(
            [mock.call()] * 2)
        self.test_obj.get_auth_providers()[0].set_auth.assert_has_calls(
            [mock.call()] * 2)
        mock_time.sleep.assert_has_calls([mock.call(1)] * 2)

    def test_clear_user_roles(self):
        # NOTE(felipemonteiro): Set the user's roles on the project to
        # include 'random' to coerce a role switch, or else it will be
        # skipped.
        self.rbac_utils_fixture.set_roles(['admin', 'member'],
                                          ['member', 'random'])
        self.test_obj._override_role()

        roles_client = self.rbac_utils_fixture.admin_roles_client

        roles_client.list_user_roles_on_project.assert_called_once_with(
            self.rbac_utils_fixture.PROJECT_ID,
            self.rbac_utils_fixture.USER_ID)
        roles_client.delete_role_from_user_on_project.\
            assert_has_calls([
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'member_id'),
                mock.call(mock.sentinel.project_id, mock.sentinel.user_id,
                          'random_id')])

    def test_override_role_context_manager_simulate_pass(self):
        """Validate that expected override_role calls are made when switching
        to admin role for success path.
        """

        mock_override_role = self.patchobject(self.test_obj, '_override_role')
        with self.test_obj.override_role():
            # Validate `override_role` public method called private method
            # `_override_role` with True.
            mock_override_role.assert_called_once_with(True)
            mock_override_role.reset_mock()
        # Validate that `override_role` switched back to admin role after
        # contextmanager.
        mock_override_role.assert_called_once_with(False)

    def test_override_role_context_manager_simulate_fail(self):
        """Validate that expected override_role calls are made when switching
        to admin role for failure path (i.e. when test raises exception).
        """
        mock_override_role = self.patchobject(self.test_obj, '_override_role')

        def _do_test():
            with self.test_obj.override_role():
                # Validate `override_role` public method called private method
                # `_override_role` with True.
                mock_override_role.assert_called_once_with(True)
                mock_override_role.reset_mock()
                # Raise exc to verify role switch works for negative case.
                raise lib_exc.Forbidden()

        # Validate that role is switched back to admin, despite test failure.
        with testtools.ExpectedException(lib_exc.Forbidden):
            _do_test()
        mock_override_role.assert_called_once_with(False)

    def test_override_role_and_validate_list(self):
        m_override_role = self.patchobject(self.test_obj, 'override_role')

        with (self.test_obj.override_role_and_validate_list(
                admin_resource_id='foo')) as ctx:
            self.assertIsInstance(ctx, rbac_utils._ValidateListContext)
            m_validate = self.patchobject(ctx, '_validate')
        m_override_role.assert_called_once_with()
        m_validate.assert_called_once()

    def test_prepare_role_inferences_mapping(self):
        self.test_obj.admin_roles_client.list_all_role_inference_rules.\
            return_value = {
                "role_inferences": [
                    {
                        "implies": [{"id": "reader_id", "name": "reader"}],
                        "prior_role": {"id": "member_id", "name": "member"}
                    },
                    {
                        "implies": [{"id": "member_id", "name": "member"}],
                        "prior_role": {"id": "admin_id", "name": "admin"}
                    }
                ]
            }

        expected_role_inferences_mapping = {
            "member_id": {"reader_id"},
            "admin_id": {"member_id", "reader_id"}
        }
        actual_role_inferences_mapping = self.test_obj.\
            _prepare_role_inferences_mapping()
        self.assertEqual(expected_role_inferences_mapping,
                         actual_role_inferences_mapping)

    def test_get_all_needed_roles(self):
        self.test_obj.__class__._role_inferences_mapping = {
            "member_id": {"reader_id"},
            "admin_id": {"member_id", "reader_id"}
        }
        self.test_obj.__class__._role_map = {
            "admin_id": "admin", "admin": "admin_id",
            "member_id": "member", "member": "member_id",
            "reader_id": "reader", "reader": "reader_id"
        }
        for roles, expected_roles in (
            (['admin'], ['admin', 'member', 'reader']),
            (['member'], ['member', 'reader']),
            (['reader'], ['reader']),
            (['custom_role'], ['custom_role']),
            (['custom_role', 'member'], ['custom_role', 'member', 'reader']),
            (['admin', 'member'], ['admin', 'member', 'reader']),
        ):
            expected_roles = sorted(expected_roles)
            actual_roles = sorted(self.test_obj.get_all_needed_roles(roles))
        self.assertEqual(expected_roles, actual_roles)


class ValidateListContextTest(base.TestCase):
    @staticmethod
    def _get_context(admin_resources=None, admin_resource_id=None):
        return rbac_utils._ValidateListContext(
            admin_resources=admin_resources,
            admin_resource_id=admin_resource_id)

    def test_incorrect_usage(self):
        # admin_resources and admin_resource_is are not assigned
        self.assertRaises(rbac_exceptions.RbacValidateListException,
                          self._get_context)

        # both admin_resources and admin_resource_is are assigned
        self.assertRaises(rbac_exceptions.RbacValidateListException,
                          self._get_context,
                          admin_resources='foo', admin_resource_id='bar')
        # empty list assigned to admin_resources
        self.assertRaises(rbac_exceptions.RbacValidateListException,
                          self._get_context, admin_resources=[])

        # ctx.resources is not assigned
        ctx = self._get_context(admin_resources='foo')
        self.assertRaises(rbac_exceptions.RbacValidateListException,
                          ctx._validate)

    def test_validate_len_negative(self):
        ctx = self._get_context(admin_resources=[1, 2, 3, 4])
        self.assertEqual(ctx._validate_len, ctx._validate_func)
        self.assertEqual(4, ctx._admin_len)
        self.assertFalse(hasattr(ctx, '_admin_resource_id'))

        # the number of resources is less than admin resources
        ctx.resources = [1, 2, 3]
        self.assertRaises(rbac_exceptions.RbacPartialResponseBody,
                          ctx._validate_len)

        # the resources is empty
        ctx.resources = []
        self.assertRaises(rbac_exceptions.RbacEmptyResponseBody,
                          ctx._validate_len)

    def test_validate_len(self):
        ctx = self._get_context(admin_resources=[1, 2, 3, 4])

        # the number of resources and admin resources are same
        ctx.resources = [1, 2, 3, 4]
        self.assertIsNone(ctx._validate_len())

    def test_validate_resource_negative(self):
        ctx = self._get_context(admin_resource_id=1)
        self.assertEqual(ctx._validate_resource, ctx._validate_func)
        self.assertEqual(1, ctx._admin_resource_id)
        self.assertFalse(hasattr(ctx, '_admin_len'))

        # there is no admin resource in the resources
        ctx.resources = [{'id': 2}, {'id': 3}]
        self.assertRaises(rbac_exceptions.RbacPartialResponseBody,
                          ctx._validate_resource)

    def test_validate_resource(self):
        ctx = self._get_context(admin_resource_id=1)

        # there is admin resource in the resources
        ctx.resources = [{'id': 1}, {'id': 2}]
        self.assertIsNone(ctx._validate_resource())

    def test_validate(self):
        ctx = self._get_context(admin_resources='foo')
        ctx.resources = 'bar'
        with mock.patch.object(ctx, '_validate_func',
                               autospec=False) as m_validate_func:
            m_validate_func.side_effect = (
                rbac_exceptions.RbacPartialResponseBody,
                None
            )
            self.assertRaises(rbac_exceptions.RbacPartialResponseBody,
                              ctx._validate)
            m_validate_func.assert_called_once()

            m_validate_func.reset_mock()
            ctx._validate()
            m_validate_func.assert_called_once()
