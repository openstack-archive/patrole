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

from tempest import config
from tempest.lib import exceptions
from tempest import test
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation as rbac_rv

CONF = config.CONF


class RBACRuleValidationTest(base.TestCase):

    def setUp(self):
        super(RBACRuleValidationTest, self).setUp()
        self.mock_args = mock.Mock(spec=test.BaseTestCase)
        self.mock_args.os_primary = mock.Mock()
        self.mock_args.rbac_utils = mock.Mock()
        self.mock_args.os_primary.credentials.project_id = \
            mock.sentinel.project_id
        self.mock_args.os_primary.credentials.user_id = \
            mock.sentinel.user_id

        CONF.set_override('rbac_test_role', 'Member', group='patrole')
        self.addCleanup(CONF.clear_override, 'rbac_test_role', group='patrole')

        self.mock_rbaclog = mock.patch.object(
            rbac_rv.RBACLOG, 'info', autospec=False).start()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_have_permission_no_exc(self, mock_authority,
                                                    mock_log):
        """Test that having permission and no exception thrown is success.

        Positive test case success scenario.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)

        mock_function = mock.Mock(__name__='foo')
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed\
            .return_value = True

        result = wrapper(self.mock_args)

        self.assertIsNone(result)
        mock_log.warning.assert_not_called()
        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_lack_permission_throw_exc(self, mock_authority,
                                                       mock_log):
        """Test that having no permission and exception thrown is success.

        Negative test case success scenario.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)

        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = exceptions.Forbidden
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed\
            .return_value = False

        result = wrapper(self.mock_args)

        self.assertIsNone(result)
        mock_log.warning.assert_not_called()
        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_forbidden_negative(self, mock_authority,
                                                mock_log):
        """Test Forbidden error is thrown and have permission fails.

        Negative test case: if Forbidden is thrown and the user should be
        allowed to perform the action, then the Forbidden exception should be
        raised.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = exceptions.Forbidden
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed\
            .return_value = True

        e = self.assertRaises(exceptions.Forbidden, wrapper, self.mock_args)
        self.assertIn(
            "Role Member was not allowed to perform sentinel.action.",
            e.__str__())
        mock_log.error.assert_called_once_with("Role Member was not allowed to"
                                               " perform sentinel.action.")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_malformed_response_positive(
            self, mock_authority_authority, mock_log):
        """Test RbacMalformedResponse error is thrown without permission passes.

        Positive test case: if RbacMalformedResponse is thrown and the user is
        not allowed to perform the action, then this is a success.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = rbac_exceptions.RbacMalformedResponse
        wrapper = decorator(mock_function)

        (mock_authority_authority.PolicyAuthority.return_value.allowed
            .return_value) = False

        result = wrapper(self.mock_args)

        self.assertIsNone(result)
        mock_log.error.assert_not_called()
        mock_log.warning.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_malformed_response_negative(
            self, mock_authority_authority, mock_log):
        """Test RbacMalformedResponse error is thrown with permission fails.

        Negative test case: if RbacMalformedResponse is thrown and the user is
        allowed to perform the action, then this is an expected failure.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = rbac_exceptions.RbacMalformedResponse
        wrapper = decorator(mock_function)

        (mock_authority_authority.PolicyAuthority.return_value.allowed
            .return_value) = True

        e = self.assertRaises(exceptions.Forbidden, wrapper, self.mock_args)
        self.assertIn(
            "Role Member was not allowed to perform sentinel.action.",
            e.__str__())

        mock_log.error.assert_called_once_with("Role Member was not allowed to"
                                               " perform sentinel.action.")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_conflicting_policies_positive(
            self, mock_authority_authority, mock_log):
        """Test RbacConflictingPolicies error is thrown without permission passes.

        Positive test case: if RbacConflictingPolicies is thrown and the user
        is not allowed to perform the action, then this is a success.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = rbac_exceptions.RbacConflictingPolicies
        wrapper = decorator(mock_function)

        (mock_authority_authority.PolicyAuthority.return_value.allowed
            .return_value) = False

        result = wrapper(self.mock_args)

        self.assertIsNone(result)
        mock_log.error.assert_not_called()
        mock_log.warning.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_conflicting_policies_negative(self,
                                                                mock_authority,
                                                                mock_log):
        """Test RbacConflictingPolicies error is thrown with permission fails.

        Negative test case: if RbacConflictingPolicies is thrown and the user
        is allowed to perform the action, then this is an expected failure.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = rbac_exceptions.RbacConflictingPolicies
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed\
            .return_value = True

        e = self.assertRaises(exceptions.Forbidden, wrapper, self.mock_args)
        self.assertIn(
            "Role Member was not allowed to perform sentinel.action.",
            e.__str__())

        mock_log.error.assert_called_once_with("Role Member was not allowed to"
                                               " perform sentinel.action.")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_expect_not_found_but_raises_forbidden(self, mock_authority,
                                                   mock_log):
        """Test that expecting 404 but getting 403 works for all scenarios.

        Tests the following scenarios:
        1) Test no permission and 404 is expected but 403 is thrown throws
           exception.
        2) Test have permission and 404 is expected but 403 is thrown throws
           exception.
        """
        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.action,
                                   expected_error_code=404)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = exceptions.Forbidden('Random message.')
        wrapper = decorator(mock_function)

        expected_error = "An unexpected exception has occurred during test: "\
            "foo, Exception was: Forbidden\nDetails: Random message."

        for allowed in [True, False]:
            mock_authority.PolicyAuthority.return_value.allowed.\
                return_value = allowed

            e = self.assertRaises(exceptions.Forbidden, wrapper,
                                  self.mock_args)
            self.assertIn(expected_error, e.__str__())
            mock_log.error.assert_called_once_with(expected_error)
            mock_log.error.reset_mock()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_expect_not_found_and_raise_not_found(self, mock_authority,
                                                  mock_log):
        """Test that expecting 404 and getting 404 works for all scenarios.

        Tests the following scenarios:
        1) Test no permission and 404 is expected and 404 is thrown succeeds.
        2) Test have permission and 404 is expected and 404 is thrown fails.

        In both cases, a LOG.warning is called with the "irregular message"
        that signals to user that a 404 was expected and caught.
        """
        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.action,
                                   expected_error_code=404)
        mock_function = mock.Mock(__name__='foo')
        mock_function.side_effect = exceptions.NotFound
        wrapper = decorator(mock_function)

        expected_errors = [
            "Role Member was not allowed to perform sentinel.action.", None
        ]

        for pos, allowed in enumerate([True, False]):
            mock_authority.PolicyAuthority.return_value.allowed\
                .return_value = allowed

            expected_error = expected_errors[pos]

            if expected_error:
                e = self.assertRaises(exceptions.Forbidden, wrapper,
                                      self.mock_args)
                self.assertIn(expected_error, e.__str__())
                mock_log.error.assert_called_once_with(expected_error)
            else:
                wrapper(self.mock_args)
                mock_log.error.assert_not_called()

            mock_log.warning.assert_called_once_with(
                "NotFound exception was caught for policy action {0}. The "
                "service {1} throws a 404 instead of a 403, which is "
                "irregular.".format(mock.sentinel.action,
                                    mock.sentinel.service))

            mock_log.warning.reset_mock()
            mock_log.error.reset_mock()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_overpermission_negative(self, mock_authority,
                                                     mock_log):
        """Test that OverPermission is correctly handled.

        Tests that case where no exception is thrown but the Patrole framework
        says that the role should not be allowed to perform the policy action.
        """
        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)

        mock_function = mock.Mock(__name__='foo')
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed\
            .return_value = False

        e = self.assertRaises(rbac_exceptions.RbacOverPermission, wrapper,
                              self.mock_args)
        self.assertIn(("OverPermission: Role Member was allowed to perform "
                       "sentinel.action"), e.__str__())
        mock_log.error.assert_called_once_with(
            'Role %s was allowed to perform %s', 'Member',
            mock.sentinel.action)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_invalid_policy_rule_throws_parsing_exception(
            self, mock_authority_authority):
        """Test that invalid policy action causes test to be skipped."""
        CONF.set_override('strict_policy_check', True, group='patrole')
        self.addCleanup(CONF.clear_override, 'strict_policy_check',
                        group='patrole')

        mock_authority_authority.PolicyAuthority.return_value.allowed.\
            side_effect = rbac_exceptions.RbacParsingException

        decorator = rbac_rv.action(mock.sentinel.service,
                                   mock.sentinel.policy_rule)
        wrapper = decorator(mock.Mock(__name__='foo'))

        e = self.assertRaises(rbac_exceptions.RbacParsingException, wrapper,
                              self.mock_args)
        self.assertEqual('Attempted to test an invalid policy file or action',
                         str(e))

        mock_authority_authority.PolicyAuthority.assert_called_once_with(
            mock.sentinel.project_id, mock.sentinel.user_id,
            mock.sentinel.service, extra_target_data={})

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_get_exception_type_404(self, _):
        """Test that getting a 404 exception type returns NotFound."""
        expected_exception = exceptions.NotFound
        expected_irregular_msg = ("NotFound exception was caught for policy "
                                  "action {0}. The service {1} throws a 404 "
                                  "instead of a 403, which is irregular.")

        actual_exception, actual_irregular_msg = \
            rbac_rv._get_exception_type(404)

        self.assertEqual(expected_exception, actual_exception)
        self.assertEqual(expected_irregular_msg, actual_irregular_msg)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_get_exception_type_403(self, _):
        """Test that getting a 404 exception type returns Forbidden."""
        expected_exception = exceptions.Forbidden
        expected_irregular_msg = None

        actual_exception, actual_irregular_msg = \
            rbac_rv._get_exception_type(403)

        self.assertEqual(expected_exception, actual_exception)
        self.assertEqual(expected_irregular_msg, actual_irregular_msg)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    def test_exception_thrown_when_type_is_not_int(self, mock_log, _):
        """Test that non-integer exception type raises error."""
        self.assertRaises(rbac_exceptions.RbacInvalidErrorCode,
                          rbac_rv._get_exception_type, "403")

        mock_log.error.assert_called_once_with("Please pass an expected error "
                                               "code. Currently supported "
                                               "codes: [403, 404]")

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    def test_exception_thrown_when_type_is_403_or_404(self, mock_log, _):
        """Test that unsupported exceptions throw error."""
        invalid_exceptions = [200, 400, 500]
        for exc in invalid_exceptions:
            self.assertRaises(rbac_exceptions.RbacInvalidErrorCode,
                              rbac_rv._get_exception_type, exc)
            mock_log.error.assert_called_once_with(
                "Please pass an expected error code. Currently supported "
                "codes: [403, 404]")

            mock_log.error.reset_mock()

    @mock.patch.object(rbac_rv, 'RBACLOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rbac_report_logging_disabled(self, mock_authority, mock_rbaclog):
        """Test case to ensure that we DON'T write logs when
        enable_reporting is False
        """
        CONF.set_override('enable_reporting', False, group='patrole_log')
        self.addCleanup(CONF.clear_override,
                        'enable_reporting', group='patrole_log')

        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)

        mock_function = mock.Mock(__name__='foo-nolog')
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        wrapper(self.mock_args)

        self.assertFalse(mock_rbaclog.info.called)

    @mock.patch.object(rbac_rv, 'RBACLOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rbac_report_logging_enabled(self, mock_authority, mock_rbaclog):
        """Test case to ensure that we DO write logs when
        enable_reporting is True
        """
        CONF.set_override('enable_reporting', True, group='patrole_log')
        self.addCleanup(CONF.clear_override,
                        'enable_reporting', group='patrole_log')

        decorator = rbac_rv.action(mock.sentinel.service, mock.sentinel.action)

        mock_function = mock.Mock(__name__='foo-log')
        wrapper = decorator(mock_function)

        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        wrapper(self.mock_args)

        mock_rbaclog.info.assert_called_once_with(
            "[Service]: %s, [Test]: %s, [Rule]: %s, "
            "[Expected]: %s, [Actual]: %s",
            mock.sentinel.service, 'foo-log',
            mock.sentinel.action,
            "Allowed",
            "Allowed")
