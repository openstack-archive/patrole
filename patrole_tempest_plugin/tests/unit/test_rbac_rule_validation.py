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

from __future__ import absolute_import

import functools
import mock
from oslo_config import cfg

import fixtures
from tempest.lib import exceptions
from tempest import manager
from tempest import test
from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation as rbac_rv
from patrole_tempest_plugin import rbac_utils
from patrole_tempest_plugin.tests.unit import fixtures as patrole_fixtures

CONF = cfg.CONF


class BaseRBACRuleValidationTest(base.TestCase):

    def setUp(self):
        super(BaseRBACRuleValidationTest, self).setUp()
        self.mock_test_args = mock.Mock(spec=test.BaseTestCase)
        self.mock_test_args.os_primary = mock.Mock(spec=manager.Manager)
        self.mock_test_args.rbac_utils = mock.Mock(
            spec_set=rbac_utils.RbacUtils)

        # Setup credentials for mock client manager.
        mock_creds = mock.Mock(user_id=mock.sentinel.user_id,
                               project_id=mock.sentinel.project_id)
        setattr(self.mock_test_args.os_primary, 'credentials', mock_creds)

        self.useFixture(
            patrole_fixtures.ConfPatcher(rbac_test_role='Member',
                                         group='patrole'))
        # Disable patrole log for unit tests.
        self.useFixture(
            patrole_fixtures.ConfPatcher(enable_reporting=False,
                                         group='patrole_log'))


class RBACRuleValidationTest(BaseRBACRuleValidationTest):
    """Test suite for validating fundamental functionality for the
    ``rbac_rule_validation`` decorator.
    """

    def setUp(self):
        super(RBACRuleValidationTest, self).setUp()
        # This behavior is tested in separate test class below.
        self.useFixture(fixtures.MockPatchObject(
            rbac_rv, '_validate_override_role_called'))

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_have_permission_no_exc(self, mock_authority,
                                                    mock_log):
        """Test that having permission and no exception thrown is success.

        Positive test case success scenario.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            pass

        test_policy(self.mock_test_args)
        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_lack_permission_throw_exc(self, mock_authority,
                                                       mock_log):
        """Test that having no permission and exception thrown is success.

        Negative test case success scenario.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            raise exceptions.Forbidden()

        test_policy(self.mock_test_args)
        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_forbidden_negative(self, mock_authority,
                                                mock_log):
        """Test RbacUnderPermissionException error is thrown and have
        permission fails.

        Negative test case: if Forbidden is thrown and the user should be
        allowed to perform the action, then the RbacUnderPermissionException
        exception should be raised.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            raise exceptions.Forbidden()

        test_re = ("Role Member was not allowed to perform the following "
                   "actions: \[%s\].*" % (mock.sentinel.action))
        self.assertRaisesRegex(
            rbac_exceptions.RbacUnderPermissionException, test_re, test_policy,
            self.mock_test_args)
        self.assertRegex(mock_log.error.mock_calls[0][1][0], test_re)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_malformed_response_positive(
            self, mock_authority, mock_log):
        """Test RbacMalformedResponse error is thrown without permission
        passes.

        Positive test case: if RbacMalformedResponse is thrown and the user is
        not allowed to perform the action, then this is a success.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            raise rbac_exceptions.RbacMalformedResponse()

        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_malformed_response_negative(
            self, mock_authority, mock_log):
        """Test RbacMalformedResponse error is thrown with permission fails.

        Negative test case: if RbacMalformedResponse is thrown and the user is
        allowed to perform the action, then this is an expected failure.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            raise rbac_exceptions.RbacMalformedResponse()

        test_re = ("Role Member was not allowed to perform the following "
                   "actions: \[%s\].*" % (mock.sentinel.action))
        self.assertRaisesRegex(
            rbac_exceptions.RbacUnderPermissionException, test_re, test_policy,
            self.mock_test_args)
        self.assertRegex(mock_log.error.mock_calls[0][1][0], test_re)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_conflicting_policies_positive(
            self, mock_authority, mock_log):
        """Test RbacConflictingPolicies error is thrown without permission
        passes.

        Positive test case: if RbacConflictingPolicies is thrown and the user
        is not allowed to perform the action, then this is a success.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            raise rbac_exceptions.RbacConflictingPolicies()

        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_rbac_conflicting_policies_negative(self,
                                                                mock_authority,
                                                                mock_log):
        """Test RbacConflictingPolicies error is thrown with permission fails.

        Negative test case: if RbacConflictingPolicies is thrown and the user
        is allowed to perform the action, then this is an expected failure.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            raise rbac_exceptions.RbacConflictingPolicies()

        test_re = ("Role Member was not allowed to perform the following "
                   "actions: \[%s\].*" % (mock.sentinel.action))
        self.assertRaisesRegex(
            rbac_exceptions.RbacUnderPermissionException, test_re, test_policy,
            self.mock_test_args)
        self.assertRegex(mock_log.error.mock_calls[0][1][0], test_re)

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
        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action],
                        expected_error_codes=[404])
        def test_policy(*args):
            raise exceptions.Forbidden('Test message')

        error_re = r'Expected .* to be raised but .* was raised instead'

        for allowed in [True, False]:
            mock_authority.PolicyAuthority.return_value.allowed.\
                return_value = allowed
            self.assertRaisesRegex(
                rbac_exceptions.RbacExpectedWrongException, error_re,
                test_policy, self.mock_test_args)
            self.assertTrue(mock_log.error.called)

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
        policy_names = ['foo:bar']

        @rbac_rv.action(mock.sentinel.service, rules=policy_names,
                        expected_error_codes=[404])
        def test_policy(*args):
            raise exceptions.NotFound()

        expected_errors = [
            ("Role Member was not allowed to perform the following "
             "actions: \['%s'\].*" % policy_names[0]),
            None
        ]

        for pos, allowed in enumerate([True, False]):
            mock_authority.PolicyAuthority.return_value.allowed\
                .return_value = allowed

            error_re = expected_errors[pos]

            if error_re:
                self.assertRaisesRegex(
                    rbac_exceptions.RbacUnderPermissionException, error_re,
                    test_policy, self.mock_test_args)
                self.assertRegex(mock_log.error.mock_calls[0][1][0], error_re)
            else:
                test_policy(self.mock_test_args)
                mock_log.error.assert_not_called()

            mock_log.warning.assert_called_with(
                "NotFound exception was caught for test %s. Expected policies "
                "which may have caused the error: %s. The service %s throws a "
                "404 instead of a 403, which is irregular",
                test_policy.__name__,
                ', '.join(policy_names),
                mock.sentinel.service)

            mock_log.warning.reset_mock()
            mock_log.error.reset_mock()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_overpermission_negative(self, mock_authority,
                                                     mock_log):
        """Test that RbacOverPermissionException is correctly handled.

        Tests that case where no exception is thrown but the Patrole framework
        says that the role should not be allowed to perform the policy action.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy_expect_forbidden(*args):
            pass

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action],
                        expected_error_codes=[404])
        def test_policy_expect_not_found(*args):
            pass

        for test_policy in (
            test_policy_expect_forbidden, test_policy_expect_not_found):

            error_re = ".*OverPermission: .* \[%s\]$" % mock.sentinel.action
            self.assertRaisesRegex(rbac_exceptions.RbacOverPermissionException,
                                   error_re, test_policy, self.mock_test_args)
            self.assertRegex(mock_log.error.mock_calls[0][1][0], error_re)
            mock_log.error.reset_mock()

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_invalid_policy_rule_raises_parsing_exception(
            self, mock_authority):
        """Test that invalid policy action causes test to raise an exception.
        """
        mock_authority.PolicyAuthority.return_value.allowed.\
            side_effect = rbac_exceptions.RbacParsingException

        @rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        def test_policy(*args):
            pass

        error_re = 'Attempted to test an invalid policy file or action'
        self.assertRaisesRegex(rbac_exceptions.RbacParsingException, error_re,
                               test_policy, self.mock_test_args)

        mock_authority.PolicyAuthority.assert_called_once_with(
            mock.sentinel.project_id, mock.sentinel.user_id,
            mock.sentinel.service, extra_target_data={})

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_get_exception_type_404(self, _):
        """Test that getting a 404 exception type returns NotFound."""
        expected_exception = exceptions.NotFound
        expected_irregular_msg = (
            "NotFound exception was caught for test %s. Expected policies "
            "which may have caused the error: %s. The service %s throws a "
            "404 instead of a 403, which is irregular")

        actual_exception, actual_irregular_msg = \
            rbac_rv._get_exception_type(404)

        self.assertEqual(expected_exception, actual_exception)
        self.assertEqual(expected_irregular_msg, actual_irregular_msg)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_get_exception_type_403(self, _):
        """Test that getting a 403 exception type returns Forbidden."""
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


class RBACRuleValidationLoggingTest(BaseRBACRuleValidationTest):
    """Test class for validating the RBAC log, dedicated to just logging
    Patrole RBAC validation work flows.
    """

    def setUp(self):
        super(RBACRuleValidationLoggingTest, self).setUp()
        # This behavior is tested in separate test class below.
        self.useFixture(fixtures.MockPatchObject(
            rbac_rv, '_validate_override_role_called'))

    @mock.patch.object(rbac_rv, 'RBACLOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rbac_report_logging_disabled(self, mock_authority, mock_rbaclog):
        """Test case to ensure that we DON'T write logs when  enable_reporting
        is False
        """
        self.useFixture(
            patrole_fixtures.ConfPatcher(enable_reporting=False,
                                         group='patrole_log'))

        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        @rbac_rv.action(mock.sentinel.service, rules=[mock.sentinel.action])
        def test_policy(*args):
            pass

        test_policy(self.mock_test_args)
        self.assertFalse(mock_rbaclog.info.called)

    @mock.patch.object(rbac_rv, 'RBACLOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rbac_report_logging_enabled(self, mock_authority, mock_rbaclog):
        """Test case to ensure that we DO write logs when enable_reporting is
        True
        """
        self.useFixture(
            patrole_fixtures.ConfPatcher(enable_reporting=True,
                                         group='patrole_log'))

        mock_authority.PolicyAuthority.return_value.allowed.return_value = True
        policy_names = ['foo:bar', 'baz:qux']

        @rbac_rv.action(mock.sentinel.service, rules=policy_names)
        def test_policy(*args):
            pass

        test_policy(self.mock_test_args)
        mock_rbaclog.info.assert_called_once_with(
            "[Service]: %s, [Test]: %s, [Rules]: %s, "
            "[Expected]: %s, [Actual]: %s",
            mock.sentinel.service,
            'test_policy',
            ', '.join(policy_names),
            "Allowed",
            "Allowed")

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_with_callable_rule(self, mock_authority,
                                                mock_log):
        """Test that a callable as the rule is evaluated correctly."""
        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        @rbac_rv.action(mock.sentinel.service,
                        rules=[lambda: mock.sentinel.action])
        def test_policy(*args):
            pass

        test_policy(self.mock_test_args)

        policy_authority = mock_authority.PolicyAuthority.return_value
        policy_authority.allowed.assert_called_with(
            mock.sentinel.action,
            CONF.patrole.rbac_test_role)

        mock_log.error.assert_not_called()

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_with_conditional_callable_rule(
            self, mock_authority, mock_log):
        """Test that a complex callable with conditional logic as the rule is
        evaluated correctly.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value = True

        def partial_func(x):
            return "foo" if x == "bar" else "qux"
        foo_callable = functools.partial(partial_func, "bar")
        bar_callable = functools.partial(partial_func, "baz")

        @rbac_rv.action(mock.sentinel.service,
                        rules=[foo_callable])
        def test_foo_policy(*args):
            pass

        @rbac_rv.action(mock.sentinel.service,
                        rules=[bar_callable])
        def test_bar_policy(*args):
            pass

        test_foo_policy(self.mock_test_args)
        policy_authority = mock_authority.PolicyAuthority.return_value
        policy_authority.allowed.assert_called_with(
            "foo",
            CONF.patrole.rbac_test_role)
        policy_authority.allowed.reset_mock()

        test_bar_policy(self.mock_test_args)
        policy_authority = mock_authority.PolicyAuthority.return_value
        policy_authority.allowed.assert_called_with(
            "qux",
            CONF.patrole.rbac_test_role)

        mock_log.error.assert_not_called()


class RBACRuleValidationNegativeTest(BaseRBACRuleValidationTest):

    def setUp(self):
        super(RBACRuleValidationNegativeTest, self).setUp()
        # This behavior is tested in separate test class below.
        self.useFixture(fixtures.MockPatchObject(
            rbac_rv, '_validate_override_role_called'))

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_invalid_service_raises_exc(self, mock_authority):
        """Test that invalid service raises the appropriate exception."""
        mock_authority.PolicyAuthority.return_value.allowed.side_effect = (
            rbac_exceptions.RbacInvalidServiceException)

        @rbac_rv.action(mock.sentinel.service, mock.sentinel.action)
        def test_policy(*args):
            pass

        self.assertRaises(rbac_exceptions.RbacInvalidServiceException,
                          test_policy, self.mock_test_args)


class RBACRuleValidationTestMultiPolicy(BaseRBACRuleValidationTest):
    """Test suite for validating multi-policy support for the
    ``rbac_rule_validation`` decorator.
    """

    def setUp(self):
        super(RBACRuleValidationTestMultiPolicy, self).setUp()
        # This behavior is tested in separate test class below.
        self.useFixture(fixtures.MockPatchObject(
            rbac_rv, '_validate_override_role_called'))

    def _assert_policy_authority_called_with(self, rules, mock_authority):
        m_authority = mock_authority.PolicyAuthority.return_value
        m_authority.allowed.assert_has_calls([
            mock.call(rule, CONF.patrole.rbac_test_role) for rule in rules
        ])

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_multi_policy_have_permission_success(
            self, mock_authority):
        """Test that when expected result is authorized and test passes that
        the overall evaluation succeeds.
        """
        mock_authority.PolicyAuthority.return_value.allowed.\
            return_value = True

        rules = [mock.sentinel.action1, mock.sentinel.action2]

        @rbac_rv.action(mock.sentinel.service, rules=rules,
                        expected_error_codes=[403, 403])
        def test_policy(*args):
            pass

        test_policy(self.mock_test_args)
        self._assert_policy_authority_called_with(rules, mock_authority)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_multi_policy_overpermission_failure(
            self, mock_authority, mock_log):
        """Test that when expected result is unauthorized and test passes that
        the overall evaluation results in an RbacOverPermissionException
        getting raised.
        """

        rules = [
            mock.sentinel.action1, mock.sentinel.action2, mock.sentinel.action3
        ]
        exp_ecodes = [403, 403, 403]

        @rbac_rv.action(mock.sentinel.service, rules=rules,
                        expected_error_codes=exp_ecodes)
        def test_policy(*args):
            pass

        def _do_test(allowed_list, fail_on_action):
            mock_authority.PolicyAuthority.return_value.allowed.side_effect = (
                allowed_list)

            error_re = ".*OverPermission: .* \[%s\]$" % fail_on_action
            self.assertRaisesRegex(
                rbac_exceptions.RbacOverPermissionException, error_re,
                test_policy, self.mock_test_args)
            mock_log.debug.assert_any_call(
                "%s: Expecting %d to be raised for policy name: %s",
                'test_policy', 403, fail_on_action)
            self.assertRegex(mock_log.error.mock_calls[0][1][0], error_re)
            mock_log.error.reset_mock()
            self._assert_policy_authority_called_with(rules, mock_authority)

        _do_test([True, True, False], mock.sentinel.action3)
        _do_test([False, True, True], mock.sentinel.action1)
        _do_test([True, False, True], mock.sentinel.action2)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_multi_policy_forbidden_success(
            self, mock_authority, mock_log):
        """Test that when the expected result is unauthorized and the test
        fails that the overall evaluation results in success.
        """

        rules = [
            mock.sentinel.action1, mock.sentinel.action2, mock.sentinel.action3
        ]
        exp_ecodes = [403, 403, 403]

        @rbac_rv.action(mock.sentinel.service, rules=rules,
                        expected_error_codes=exp_ecodes)
        def test_policy(*args):
            raise exceptions.Forbidden()

        def _do_test(allowed_list, fail_on_action):
            mock_authority.PolicyAuthority.return_value.allowed.\
                side_effect = allowed_list
            test_policy(self.mock_test_args)
            mock_log.debug.assert_called_with(
                "%s: Expecting %d to be raised for policy name: %s",
                'test_policy', 403, fail_on_action)
            mock_log.error.assert_not_called()
            self._assert_policy_authority_called_with(rules, mock_authority)

        _do_test([True, True, False], mock.sentinel.action3)
        _do_test([False, True, True], mock.sentinel.action1)
        _do_test([True, False, True], mock.sentinel.action2)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_multi_policy_forbidden_failure(
            self, mock_authority, mock_log):
        """Test that when the expected result is authorized and the test
        fails (with a Forbidden error code) that the overall evaluation
        results in a RbacUnderPermissionException getting raised.
        """

        # NOTE: Avoid mock.sentinel here due to weird sorting with them.
        rules = ['action1', 'action2', 'action3']

        @rbac_rv.action(mock.sentinel.service, rules=rules,
                        expected_error_codes=[403, 403, 403])
        def test_policy(*args):
            raise exceptions.Forbidden()

        mock_authority.PolicyAuthority.return_value.allowed\
            .return_value = True

        error_re = ("Role Member was not allowed to perform the following "
                    "actions: %s. Expected allowed actions: %s. Expected "
                    "disallowed actions: []." % (rules, rules)).replace(
                        '[', '\[').replace(']', '\]')
        self.assertRaisesRegex(
            rbac_exceptions.RbacUnderPermissionException, error_re,
            test_policy, self.mock_test_args)
        self.assertRegex(mock_log.error.mock_calls[0][1][0], error_re)
        self._assert_policy_authority_called_with(rules, mock_authority)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_multi_actions_forbidden(
            self, mock_authority, mock_log):
        """Test that when the expected result is Forbidden because
        two of the actions fail and the first action specifies 403,
        verify that the overall evaluation results in success.
        """

        rules = [
            mock.sentinel.action1, mock.sentinel.action2, mock.sentinel.action3
        ]
        exp_ecodes = [403, 403, 404]

        @rbac_rv.action(mock.sentinel.service, rules=rules,
                        expected_error_codes=exp_ecodes)
        def test_policy(*args):
            raise exceptions.Forbidden()

        def _do_test(allowed_list, fail_on_action):
            mock_authority.PolicyAuthority.return_value.allowed.\
                side_effect = allowed_list
            test_policy(self.mock_test_args)
            mock_log.debug.assert_called_with(
                "%s: Expecting %d to be raised for policy name: %s",
                'test_policy', 403, fail_on_action)
            mock_log.error.assert_not_called()
            self._assert_policy_authority_called_with(rules, mock_authority)

        _do_test([False, True, False], mock.sentinel.action1)
        _do_test([False, False, True], mock.sentinel.action1)

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_multi_actions_notfound(
            self, mock_authority, mock_log):
        """Test that when the expected result is not found because
        two of the actions fail and the first action specifies 404,
        verify that the overall evaluation results in success.
        """

        rules = [
            'mock.sentinel.action1', 'mock.sentinel.action2',
            'mock.sentinel.action3', 'mock.sentinel.action4'
        ]
        exp_ecodes = [403, 404, 403, 403]

        @rbac_rv.action(mock.sentinel.service, rules=rules,
                        expected_error_codes=exp_ecodes)
        def test_policy(*args):
            raise exceptions.NotFound()

        def _do_test(allowed_list, fail_on_action):
            mock_authority.PolicyAuthority.return_value.allowed.\
                side_effect = allowed_list
            test_policy(self.mock_test_args)
            mock_log.debug.assert_called_with(
                "%s: Expecting %d to be raised for policy name: %s",
                'test_policy', 404, fail_on_action)
            mock_log.error.assert_not_called()
            self._assert_policy_authority_called_with(rules, mock_authority)

        _do_test([True, False, False, True], 'mock.sentinel.action2')
        _do_test([True, False, True, False], 'mock.sentinel.action2')

    def test_prepare_multi_policy_allowed_usages(self):

        def _do_test(rules, ecodes, exp_rules, exp_ecodes):
            rule_list, ec_list = rbac_rv._prepare_multi_policy(rules, ecodes)
            self.assertEqual(rule_list, exp_rules)
            self.assertEqual(ec_list, exp_ecodes)

        # Validate that expected_error_codes defaults to 403 when no values
        # are provided.
        _do_test(["rule1"], None, ["rule1"], [403])

        # Validate that `len(rules) == len(expected_error_codes)` works when
        # both == 1.
        _do_test(["rule1"], [403], ["rule1"], [403])

        # Validate that `len(rules) == len(expected_error_codes)` works when
        # both are > 1.
        _do_test(["rule1", "rule2"], [403, 404],
                 ["rule1", "rule2"], [403, 404])

        # Validate that when only a default expected_error_code argument is
        # provided, that default value and other default values (403) are
        # filled into the expected_error_codes list.
        # Example:
        #     @rbac_rv.action(service, rules=[<rule>, <rule>])
        #     def test_policy(*args):
        #        ...
        _do_test(["rule1", "rule2"], None,
                 ["rule1", "rule2"], [403, 403])

    @mock.patch.object(rbac_rv, 'LOG', autospec=True)
    def test_prepare_multi_policy_disallowed_usages(self, mock_log):

        def _do_test(rules, ecodes):
            rule_list, ec_list = rbac_rv._prepare_multi_policy(rules, ecodes)

        error_re = ("The `expected_error_codes` list is not the same length"
                    " as the `rules` list.")
        # When len(rules) > 1 then len(expected_error_codes) must be same len.
        self.assertRaisesRegex(ValueError, error_re, _do_test,
                               ["rule1", "rule2"], [403])
        # When len(expected_error_codes) > 1 len(rules) must be same len.
        self.assertRaisesRegex(ValueError, error_re, _do_test, ["rule1"],
                               [403, 404])
        error_re = ("The `rules` list must be provided if using the "
                    "`expected_error_codes` list.")
        # When expected_error_codes is provided rules must be as well.
        self.assertRaisesRegex(ValueError, error_re, _do_test, None, [404])


class RBACOverrideRoleValidationTest(BaseRBACRuleValidationTest):
    """Class for validating that untimely exceptions (outside
    ``override_role`` is called) result in test failures.

    This regression tests false positives caused by test exceptions matching
    the expected exception before or after the ``override_role`` context is
    called. Also tests case where ``override_role`` is never called which is
    an invalid Patrole test.

    """

    def setUp(self):
        super(RBACOverrideRoleValidationTest, self).setUp()

        # Mixin automatically initializes __override_role_called to False.
        class FakeRbacTest(rbac_utils.RbacUtilsMixin, test.BaseTestCase):
            def runTest(self):
                pass

        # Stub out problematic function calls.
        FakeRbacTest.os_primary = mock.Mock(spec=manager.Manager)
        FakeRbacTest.rbac_utils = self.useFixture(
            patrole_fixtures.RbacUtilsFixture())
        mock_creds = mock.Mock(user_id=mock.sentinel.user_id,
                               project_id=mock.sentinel.project_id)
        setattr(FakeRbacTest.os_primary, 'credentials', mock_creds)
        setattr(FakeRbacTest.os_primary, 'auth_provider', mock.Mock())

        self.parent_class = FakeRbacTest

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_override_role_called_inside_ctx(self,
                                                             mock_authority):
        """Test success case when the expected exception is raised within the
        override_role context.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        class ChildRbacTest(self.parent_class):

            @rbac_rv.action(mock.sentinel.service, rules=["fake:rule"],
                            expected_error_codes=[404])
            def test_called(self_):
                with self_.rbac_utils.real_override_role(self_):
                    raise exceptions.NotFound()

        child_test = ChildRbacTest()
        child_test.test_called()

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_override_role_patrole_exception_ignored(
            self, mock_authority):
        """Test success case where Patrole exception is raised (which is
        valid in case of e.g. RbacMalformedException) after override_role
        passes.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            True

        class ChildRbacTest(self.parent_class):

            @rbac_rv.action(mock.sentinel.service, rules=["fake:rule"],
                            expected_error_codes=[404])
            def test_called(self_):
                with self_.rbac_utils.real_override_role(self_):
                    pass
                # Instances of BasePatroleException don't count as they are
                # part of the validation work flow.
                raise rbac_exceptions.BasePatroleException()

        child_test = ChildRbacTest()
        self.assertRaises(rbac_exceptions.BasePatroleException,
                          child_test.test_called)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_override_role_called_before_ctx(self,
                                                             mock_authority):
        """Test failure case when an exception that happens before
        ``override_role`` context, even if it is the expected exception,
        raises ``RbacOverrideRoleException``.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        # This behavior should work for supported (NotFound/Forbidden) and
        # miscellaneous exceptions alike.
        for exception_type in (exceptions.NotFound,
                               Exception):
            class ChildRbacTest(self.parent_class):

                @rbac_rv.action(mock.sentinel.service, rules=["fake:rule"],
                                expected_error_codes=[404])
                def test_called_before(self_):
                    raise exception_type()

            child_test = ChildRbacTest()
            test_re = ".*before.*"
            self.assertRaisesRegex(rbac_exceptions.RbacOverrideRoleException,
                                   test_re, child_test.test_called_before)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_override_role_called_after_ctx(self,
                                                            mock_authority):
        """Test failure case when an exception that happens before
        ``override_role`` context, even if it is the expected exception,
        raises ``RbacOverrideRoleException``.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        # This behavior should work for supported (NotFound/Forbidden) and
        # miscellaneous exceptions alike.
        for exception_type in (exceptions.NotFound,
                               Exception):
            class ChildRbacTest(self.parent_class):

                @rbac_rv.action(mock.sentinel.service, rules=["fake:rule"],
                                expected_error_codes=[404])
                def test_called_after(self_):
                    with self_.rbac_utils.real_override_role(self_):
                        pass
                    # Simulates a test tearDown failure or some such.
                    raise exception_type()

            child_test = ChildRbacTest()
            test_re = ".*after.*"
            self.assertRaisesRegex(rbac_exceptions.RbacOverrideRoleException,
                                   test_re, child_test.test_called_after)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_override_role_never_called(self, mock_authority):
        """Test failure case where override_role is **never** called."""
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        class ChildRbacTest(self.parent_class):

            @rbac_rv.action(mock.sentinel.service, rules=["fake:rule"],
                            expected_error_codes=[404])
            def test_never_called(self_):
                pass

        child_test = ChildRbacTest()
        test_re = ".*missing required `override_role` call.*"
        self.assertRaisesRegex(rbac_exceptions.RbacOverrideRoleException,
                               test_re, child_test.test_never_called)

    @mock.patch.object(rbac_rv, 'policy_authority', autospec=True)
    def test_rule_validation_override_role_sequential_test_calls(
            self, mock_authority):
        """Test success/failure scenarios above across sequential test calls.
        """
        mock_authority.PolicyAuthority.return_value.allowed.return_value =\
            False

        class ChildRbacTest(self.parent_class):

            @rbac_rv.action(mock.sentinel.service, rules=["fake:rule1"],
                            expected_error_codes=[404])
            def test_called(self_):
                with self_.rbac_utils.real_override_role(self_):
                    raise exceptions.NotFound()

            @rbac_rv.action(mock.sentinel.service, rules=["fake:rule2"],
                            expected_error_codes=[404])
            def test_called_before(self_):
                raise exceptions.NotFound()

        test_re = ".*before.*"

        # Test case where override role is called in first test but *not* in
        # second test.
        child_test1 = ChildRbacTest()
        child_test1.test_called()
        self.assertRaisesRegex(rbac_exceptions.RbacOverrideRoleException,
                               test_re, child_test1.test_called_before)

        # Test case where override role is *not* called in first test but is
        # in second test.
        child_test2 = ChildRbacTest()
        self.assertRaisesRegex(rbac_exceptions.RbacOverrideRoleException,
                               test_re, child_test2.test_called_before)
        child_test2.test_called()
