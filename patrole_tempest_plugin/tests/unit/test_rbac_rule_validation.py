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

import mock
import testtools

from patrole_tempest_plugin import rbac_auth
from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation as rbac_rv

from tempest import config
from tempest.lib import exceptions
from tempest import test
from tempest.tests import base

CONF = config.CONF


class RBACRuleValidationTest(base.TestCase):

    def setUp(self):
        super(RBACRuleValidationTest, self).setUp()
        self.mock_args = mock.Mock(spec=test.BaseTestCase)
        self.mock_args.auth_provider = mock.Mock()
        self.mock_args.rbac_utils = mock.Mock()
        self.mock_args.auth_provider.credentials.tenant_id = \
            mock.sentinel.tenant_id
        self.mock_args.auth_provider.credentials.user_id = \
            mock.sentinel.user_id

        CONF.set_override('rbac_test_role', 'Member', group='rbac',
                          enforce_type=True)
        self.addCleanup(CONF.clear_override, 'rbac_test_role', group='rbac')

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_happy_path(self, mock_auth):
        decorator = rbac_rv.action("", "")
        mock_function = mock.Mock()
        wrapper = decorator(mock_function)
        wrapper((self.mock_args))
        self.assertTrue(mock_function.called)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_forbidden(self, mock_auth, mock_log):
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock()
        mock_function.side_effect = exceptions.Forbidden
        wrapper = decorator(mock_function)

        e = self.assertRaises(exceptions.Forbidden, wrapper, self.mock_args)
        self.assertIn(
            "Role Member was not allowed to perform sentinel.action.",
            e.__str__())
        mock_log.error.assert_called_once_with("Role Member was not allowed to"
                                               " perform sentinel.action.")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_expect_not_found_but_raises_forbidden(self, mock_auth, mock_log):
        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.action,
                                   expected_error_code=404)
        mock_function = mock.Mock()
        mock_function.side_effect = exceptions.NotFound
        wrapper = decorator(mock_function)

        e = self.assertRaises(exceptions.Forbidden, wrapper, self.mock_args)
        self.assertIn(
            "Role Member was not allowed to perform sentinel.action.",
            e.__str__())
        mock_log.error.assert_called_once_with("Role Member was not allowed to"
                                               " perform sentinel.action.")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_rbac_action_failed(self, mock_auth, mock_log):
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock()
        mock_function.side_effect = rbac_exceptions.RbacActionFailed
        wrapper = decorator(mock_function)

        e = self.assertRaises(exceptions.Forbidden, wrapper, self.mock_args)
        self.assertIn(
            "Role Member was not allowed to perform sentinel.action.",
            e.__str__())

        mock_log.error.assert_called_once_with("Role Member was not allowed to"
                                               " perform sentinel.action.")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_not_allowed(self, mock_auth, mock_log):
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)

        mock_function = mock.Mock()
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        e = self.assertRaises(rbac_exceptions.RbacOverPermission, wrapper,
                              self.mock_args)
        self.assertIn(("OverPermission: Role Member was allowed to perform "
                      "sentinel.action"), e.__str__())

        mock_log.error.assert_called_once_with(
            "Role Member was allowed to perform sentinel.action")

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_forbidden_not_allowed(self, mock_auth):
        decorator = rbac_rv.action("", "")

        mock_function = mock.Mock()
        mock_function.side_effect = exceptions.Forbidden
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        self.assertIsNone(wrapper(self.mock_args))

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_expect_not_found_and_not_allowed(self, mock_auth, mock_log):
        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.action,
                                   expected_error_code=404)

        mock_function = mock.Mock()
        mock_function.side_effect = exceptions.NotFound
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        self.assertIsNone(wrapper(self.mock_args))

        mock_log.warning.assert_called_once_with(
            'NotFound exception was caught for policy action sentinel.action. '
            'The service sentinel.service throws a 404 instead of a 403, '
            'which is irregular.')
        mock_log.error.assert_not_called()

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_rbac_action_failed_not_allowed(self, mock_auth):
        decorator = rbac_rv.action("", "")

        mock_function = mock.Mock()
        mock_function.side_effect = rbac_exceptions.RbacActionFailed
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        self.assertIsNone(wrapper(self.mock_args))

    @mock.patch.object(rbac_auth, 'rbac_policy_parser', autospec=True)
    def test_invalid_policy_rule_throws_skip_exception(
            self, mock_rbac_policy_parser):
        mock_rbac_policy_parser.RbacPolicyParser.return_value.allowed.\
            side_effect = rbac_exceptions.RbacParsingException

        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.policy_rule)
        wrapper = decorator(mock.Mock())

        e = self.assertRaises(testtools.TestCase.skipException, wrapper,
                              self.mock_args)
        self.assertEqual('Attempted to test an invalid policy file or action',
                         str(e))

        mock_rbac_policy_parser.RbacPolicyParser.assert_called_once_with(
            mock.sentinel.tenant_id, mock.sentinel.user_id,
            mock.sentinel.service)

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_get_exception_type_404(self, mock_auth):
        expected_exception = exceptions.NotFound
        expected_irregular_msg = ("NotFound exception was caught for policy "
                                  "action {0}. The service {1} throws a 404 "
                                  "instead of a 403, which is irregular.")

        actual_exception, actual_irregular_msg = \
            rbac_rv._get_exception_type(404)

        self.assertEqual(expected_exception, actual_exception)
        self.assertEqual(expected_irregular_msg, actual_irregular_msg)

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_get_exception_type_403(self, mock_auth):
        expected_exception = exceptions.Forbidden
        expected_irregular_msg = None

        actual_exception, actual_irregular_msg = \
            rbac_rv._get_exception_type(403)

        self.assertEqual(expected_exception, actual_exception)
        self.assertEqual(expected_irregular_msg, actual_irregular_msg)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_exception_thrown_when_type_is_not_int(self, mock_auth, mock_log):
        self.assertRaises(rbac_exceptions.RbacInvalidErrorCode,
                          rbac_rv._get_exception_type, "403")

        mock_log.error.assert_called_once_with("Please pass an expected error "
                                               "code. Currently supported "
                                               "codes: [403, 404]")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    def test_rbac_decorator_with_admin_only_and_have_permission(self,
                                                                mock_log):
        CONF.set_override('rbac_test_role', 'admin', group='rbac',
                          enforce_type=True)
        self.addCleanup(CONF.clear_override, 'rbac_test_role', group='rbac')

        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.policy_rule,
                                   admin_only=True)
        wrapper = decorator(mock.Mock(side_effect=None))
        wrapper(self.mock_args)

        mock_log.info.assert_called_once_with(
            "As admin_only is True, only admin role should be allowed to "
            "perform the API. Skipping oslo.policy check for policy action "
            "{0}.".format(mock.sentinel.policy_rule))

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    def test_rbac_decorator_with_admin_only_and_lack_permission(self,
                                                                mock_log):
        CONF.set_override('rbac_test_role', 'Member', group='rbac',
                          enforce_type=True)
        self.addCleanup(CONF.clear_override, 'rbac_test_role', group='rbac')

        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.policy_rule,
                                   admin_only=True)
        wrapper = decorator(mock.Mock(side_effect=exceptions.Forbidden))
        wrapper(self.mock_args)

        mock_log.info.assert_called_once_with(
            "As admin_only is True, only admin role should be allowed to "
            "perform the API. Skipping oslo.policy check for policy action "
            "{0}.".format(mock.sentinel.policy_rule))
