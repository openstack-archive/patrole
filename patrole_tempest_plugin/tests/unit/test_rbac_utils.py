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
from tempest import test
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
        error_re = (".*Following roles were not found: admin. Available "
                    "roles: member.")
        self.assertRaisesRegex(rbac_exceptions.RbacResourceSetupFailed,
                               error_re, self.rbac_utils.override_role)

    def test_override_role_with_missing_rbac_role(self):
        self.rbac_utils.set_roles('admin')
        error_re = (".*Following roles were not found: member. Available "
                    "roles: admin.")
        self.assertRaisesRegex(rbac_exceptions.RbacResourceSetupFailed,
                               error_re, self.rbac_utils.override_role)

    def test_override_role_to_admin_role(self):
        self.rbac_utils.override_role()

        mock_test_obj = self.rbac_utils.mock_test_obj
        roles_client = self.rbac_utils.admin_roles_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_called_once_with(
            self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID, 'admin_id')
        mock_test_obj.get_auth_providers()[0].clear_auth\
            .assert_called_once_with()
        mock_test_obj.get_auth_providers()[0].set_auth\
            .assert_called_once_with()
        mock_time.sleep.assert_called_once_with(1)

    def test_override_role_to_admin_role_avoids_role_switch(self):
        self.rbac_utils.set_roles(['admin', 'member'], 'admin')
        self.rbac_utils.override_role()

        roles_client = self.rbac_utils.admin_roles_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_not_called()
        mock_time.sleep.assert_not_called()

    def test_override_role_to_member_role(self):
        self.rbac_utils.override_role(True)

        mock_test_obj = self.rbac_utils.mock_test_obj
        roles_client = self.rbac_utils.admin_roles_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id'),
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'member_id')
        ])
        mock_test_obj.get_auth_providers()[0].clear_auth.assert_has_calls(
            [mock.call()] * 2)
        mock_test_obj.get_auth_providers()[0].set_auth.assert_has_calls(
            [mock.call()] * 2)
        mock_time.sleep.assert_has_calls([mock.call(1)] * 2)

    def test_override_role_to_member_role_avoids_role_switch(self):
        self.rbac_utils.set_roles(['admin', 'member'], 'member')
        self.rbac_utils.override_role(True)

        roles_client = self.rbac_utils.admin_roles_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id')
        ])
        mock_time.sleep.assert_called_once_with(1)

    def test_override_role_to_member_role_then_admin_role(self):
        self.rbac_utils.override_role(True, False)

        mock_test_obj = self.rbac_utils.mock_test_obj
        roles_client = self.rbac_utils.admin_roles_client
        mock_time = self.rbac_utils.mock_time

        roles_client.create_user_role_on_project.assert_has_calls([
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id'),
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'member_id'),
            mock.call(self.rbac_utils.PROJECT_ID, self.rbac_utils.USER_ID,
                      'admin_id')
        ])
        mock_test_obj.get_auth_providers()[0].clear_auth.assert_has_calls(
            [mock.call()] * 3)
        mock_test_obj.get_auth_providers()[0].set_auth.assert_has_calls(
            [mock.call()] * 3)
        mock_time.sleep.assert_has_calls([mock.call(1)] * 3)

    def test_clear_user_roles(self):
        # NOTE(felipemonteiro): Set the user's roles on the project to
        # include 'random' to coerce a role switch, or else it will be
        # skipped.
        self.rbac_utils.set_roles(['admin', 'member'], ['member', 'random'])
        self.rbac_utils.override_role()

        roles_client = self.rbac_utils.admin_roles_client

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

    @mock.patch.object(rbac_utils.RbacUtils, '_override_role',
                       autospec=True)
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

    def test_override_role_and_validate_list(self):
        self.patchobject(rbac_utils.RbacUtils, '_override_role')
        test_obj = mock.MagicMock()
        _rbac_utils = rbac_utils.RbacUtils(test_obj)
        m_override_role = self.patchobject(_rbac_utils, 'override_role')

        with (_rbac_utils.override_role_and_validate_list(
                test_obj, 'foo')) as ctx:
            self.assertIsInstance(ctx, rbac_utils._ValidateListContext)
            m_validate = self.patchobject(ctx, '_validate')
        m_override_role.assert_called_once_with(test_obj)
        m_validate.assert_called_once()


class RBACUtilsMixinTest(base.TestCase):

    def setUp(self):
        super(RBACUtilsMixinTest, self).setUp()

        class FakeRbacTest(rbac_utils.RbacUtilsMixin, test.BaseTestCase):

            @classmethod
            def setup_clients(cls):
                super(FakeRbacTest, cls).setup_clients()
                cls.setup_rbac_utils()

            def runTest(self):
                pass

        self.parent_class = FakeRbacTest

    def test_setup_rbac_utils(self):
        """Validate that the child class has the `rbac_utils` attribute after
        running parent class's `cls.setup_rbac_utils`.
        """
        class ChildRbacTest(self.parent_class):
            pass

        child_test = ChildRbacTest()

        with mock.patch.object(rbac_utils.RbacUtils, '__init__',
                               lambda *args: None):
            child_test.setUpClass()

        self.assertTrue(hasattr(child_test, 'rbac_utils'))
        self.assertIsInstance(child_test.rbac_utils, rbac_utils.RbacUtils)


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
