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

import functools
import logging
import sys

from oslo_log import versionutils
from oslo_utils import excutils
import six

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test

from patrole_tempest_plugin import policy_authority
from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import requirements_authority

CONF = config.CONF
LOG = logging.getLogger(__name__)

_SUPPORTED_ERROR_CODES = [403, 404]
_DEFAULT_ERROR_CODE = 403

RBACLOG = logging.getLogger('rbac_reporting')


def action(service,
           rule='',
           rules=None,
           expected_error_code=_DEFAULT_ERROR_CODE,
           expected_error_codes=None,
           extra_target_data=None):
    """A decorator for verifying OpenStack policy enforcement.

    A decorator which allows for positive and negative RBAC testing. Given:

    * an OpenStack service,
    * a policy action (``rule``) enforced by that service, and
    * the test role defined by ``[patrole] rbac_test_role``

    determines whether the test role has sufficient permissions to perform an
    API call that enforces the ``rule``.

    This decorator should only be applied to an instance or subclass of
    ``tempest.test.BaseTestCase``.

    The result from ``_is_authorized`` is used to determine the *expected*
    test result. The *actual* test result is determined by running the
    Tempest test this decorator applies to.

    Below are the following possibilities from comparing the *expected* and
    *actual* results:

    1) If *expected* is True and the test passes (*actual*), this is a success.
    2) If *expected* is True and the test fails (*actual*), this results in a
       ``RbacUnderPermissionException`` exception failure.
    3) If *expected* is False and the test passes (*actual*), this results in
       an ``RbacOverPermissionException`` exception failure.
    4) If *expected* is False and the test fails (*actual*), this is a success.

    As such, negative and positive testing can be applied using this decorator.

    :param str service: An OpenStack service. Examples: "nova" or "neutron".
    :param rule: (DEPRECATED) A policy action defined in a policy.json file
        or in code. Also accepts a callable that returns a policy action.
    :type rule: str or callable
    :param rules: A list of policy actions defined in a policy.json file
        or in code. The rules are logical-ANDed together to derive the expected
        result. Also accepts list of callables that return a policy action.

        .. note::

            Patrole currently only supports custom JSON policy files.

    :type rules: list[str] or list[callable]
    :param int expected_error_code: (DEPRECATED) Overrides default value of 403
        (Forbidden) with endpoint-specific error code. Currently only supports
        403 and 404. Support for 404 is needed because some services, like
        Neutron, intentionally throw a 404 for security reasons.

        .. warning::

            A 404 should not be provided *unless* the endpoint masks a
            ``Forbidden`` exception as a ``NotFound`` exception.

    :param list expected_error_codes: When the ``rules`` list parameter is
        used, then this list indicates the expected error code to use if one
        of the rules does not allow the role being tested. This list must
        coincide with and its elements remain in the same order as the rules
        in the rules list.

        Example::

            rules=["api_action1", "api_action2"]
            expected_error_codes=[404, 403]

        a) If api_action1 fails and api_action2 passes, then the expected
           error code is 404.
        b) if api_action2 fails and api_action1 passes, then the expected
           error code is 403.
        c) if both api_action1 and api_action2 fail, then the expected error
           code is the first error seen (404).

        If it is not passed, then it is defaulted to 403.

    :param dict extra_target_data: Dictionary, keyed with ``oslo.policy``
        generic check names, whose values are string literals that reference
        nested ``tempest.test.BaseTestCase`` attributes. Used by
        ``oslo.policy`` for performing matching against attributes that are
        sent along with the API calls. Example::

            extra_target_data={
                "target.token.user_id":
                "os_alt.auth_provider.credentials.user_id"
            })

    :raises RbacInvalidServiceException: If ``service`` is invalid.
    :raises RbacUnderPermissionException: For item (2) above.
    :raises RbacOverPermissionException: For item (3) above.
    :raises RbacExpectedWrongException: When a 403 is expected but a 404
        is raised instead or vice versa.

    Examples::

        @rbac_rule_validation.action(
            service="nova", rule="os_compute_api:os-agents")
        def test_list_agents_rbac(self):
            # The call to `override_role` is mandatory.
            with self.rbac_utils.override_role(self):
                self.agents_client.list_agents()
    """

    if extra_target_data is None:
        extra_target_data = {}

    rules, expected_error_codes = _prepare_multi_policy(rule, rules,
                                                        expected_error_code,
                                                        expected_error_codes)

    def decorator(test_func):
        role = CONF.patrole.rbac_test_role

        @functools.wraps(test_func)
        def wrapper(*args, **kwargs):
            if args and isinstance(args[0], test.BaseTestCase):
                test_obj = args[0]
            else:
                raise rbac_exceptions.RbacResourceSetupFailed(
                    '`rbac_rule_validation` decorator can only be applied to '
                    'an instance of `tempest.test.BaseTestCase`.')

            allowed = True
            disallowed_rules = []
            for rule in rules:
                _allowed = _is_authorized(
                    test_obj, service, rule, extra_target_data)
                if not _allowed:
                    disallowed_rules.append(rule)
                allowed = allowed and _allowed

            exp_error_code = expected_error_code
            if disallowed_rules:
                # Choose the first disallowed rule and expect the error
                # code corresponding to it.
                first_error_index = rules.index(disallowed_rules[0])
                exp_error_code = expected_error_codes[first_error_index]
                LOG.debug("%s: Expecting %d to be raised for policy name: %s",
                          test_func.__name__, exp_error_code,
                          disallowed_rules[0])

            expected_exception, irregular_msg = _get_exception_type(
                exp_error_code)

            caught_exception = None
            test_status = 'Allowed'

            try:
                test_func(*args, **kwargs)
            except rbac_exceptions.RbacInvalidServiceException:
                with excutils.save_and_reraise_exception():
                    msg = ("%s is not a valid service." % service)
                    # FIXME(felipemonteiro): This test_status is logged too
                    # late. Need a function to log it before re-raising.
                    test_status = ('Error, %s' % (msg))
                    LOG.error(msg)
            except (expected_exception,
                    rbac_exceptions.RbacMalformedResponse) as actual_exception:
                caught_exception = actual_exception
                test_status = 'Denied'

                if irregular_msg:
                    LOG.warning(irregular_msg,
                                test_func.__name__,
                                ', '.join(rules),
                                service)

                if allowed:
                    msg = ("Role %s was not allowed to perform the following "
                           "actions: %s. Expected allowed actions: %s. "
                           "Expected disallowed actions: %s." % (
                               role, sorted(rules),
                               sorted(set(rules) - set(disallowed_rules)),
                               sorted(disallowed_rules)))
                    LOG.error(msg)
                    raise rbac_exceptions.RbacUnderPermissionException(
                        "%s Exception was: %s" % (msg, actual_exception))
            except Exception as actual_exception:
                caught_exception = actual_exception

                if _check_for_expected_mismatch_exception(expected_exception,
                                                          actual_exception):
                    LOG.error('Expected and actual exceptions do not match. '
                              'Expected: %s. Actual: %s.',
                              expected_exception,
                              actual_exception.__class__)
                    raise rbac_exceptions.RbacExpectedWrongException(
                        expected=expected_exception,
                        actual=actual_exception.__class__,
                        exception=actual_exception)
                else:
                    with excutils.save_and_reraise_exception():
                        exc_info = sys.exc_info()
                        error_details = six.text_type(exc_info[1])
                        msg = ("An unexpected exception has occurred during "
                               "test: %s. Exception was: %s" % (
                                   test_func.__name__, error_details))
                        test_status = 'Error, %s' % (error_details)
                        LOG.error(msg)
            else:
                if not allowed:
                    msg = (
                        "OverPermission: Role %s was allowed to perform the "
                        "following disallowed actions: %s" % (
                            role, sorted(disallowed_rules)
                        )
                    )
                    LOG.error(msg)
                    raise rbac_exceptions.RbacOverPermissionException(msg)
            finally:
                if CONF.patrole_log.enable_reporting:
                    RBACLOG.info(
                        "[Service]: %s, [Test]: %s, [Rules]: %s, "
                        "[Expected]: %s, [Actual]: %s",
                        service, test_func.__name__, ', '.join(rules),
                        "Allowed" if allowed else "Denied",
                        test_status)

                # Sanity-check that ``override_role`` was called to eliminate
                # false-positives and bad test flows resulting from exceptions
                # getting raised too early, too late or not at all, within
                # the scope of an RBAC test.
                _validate_override_role_called(
                    test_obj,
                    actual_exception=caught_exception)

        return wrapper
    return decorator


def _prepare_multi_policy(rule, rules, exp_error_code, exp_error_codes):
    if exp_error_codes:
        if not rules:
            msg = ("The `rules` list must be provided if using the "
                   "`expected_error_codes` list.")
            raise ValueError(msg)
        if len(rules) != len(exp_error_codes):
            msg = ("The `expected_error_codes` list is not the same length "
                   "as the `rules` list.")
            raise ValueError(msg)
        if exp_error_code:
            deprecation_msg = (
                "The `exp_error_code` argument has been deprecated in favor "
                "of `exp_error_codes` and will be removed in a future "
                "version.")
            versionutils.report_deprecated_feature(LOG, deprecation_msg)
            LOG.debug("The `exp_error_codes` argument will be used instead of "
                      "`exp_error_code`.")
        if not isinstance(exp_error_codes, (tuple, list)):
            exp_error_codes = [exp_error_codes]
    else:
        exp_error_codes = []
        if exp_error_code:
            exp_error_codes.append(exp_error_code)

    if rules is None:
        rules = []
    elif not isinstance(rules, (tuple, list)):
        rules = [rules]
    if rule:
        deprecation_msg = (
            "The `rule` argument has been deprecated in favor of `rules` "
            "and will be removed in a future version.")
        versionutils.report_deprecated_feature(LOG, deprecation_msg)
        if rules:
            LOG.debug("The `rules` argument will be used instead of `rule`.")
        else:
            rules.append(rule)

    # Fill in the exp_error_codes if needed. This is needed for the scenarios
    # where no exp_error_codes array is provided, so the error codes must be
    # set to the default error code value and there must be the same number
    # of error codes as rules.
    num_ecs = len(exp_error_codes)
    num_rules = len(rules)
    if (num_ecs < num_rules):
        for i in range(num_rules - num_ecs):
            exp_error_codes.append(_DEFAULT_ERROR_CODE)

    evaluated_rules = [
        r() if callable(r) else r for r in rules
    ]

    return evaluated_rules, exp_error_codes


def _is_authorized(test_obj, service, rule, extra_target_data):
    """Validates whether current RBAC role has permission to do policy action.

    :param test_obj: An instance or subclass of ``tempest.test.BaseTestCase``.
    :param service: The OpenStack service that enforces ``rule``.
    :param rule: The name of the policy action. Examples include
        "identity:create_user" or "os_compute_api:os-agents".
    :param extra_target_data: Dictionary, keyed with ``oslo.policy`` generic
        check names, whose values are string literals that reference nested
        ``tempest.test.BaseTestCase`` attributes. Used by ``oslo.policy`` for
        performing matching against attributes that are sent along with the API
        calls.

    :returns: True if the current RBAC role can perform the policy action,
        else False.

    :raises RbacResourceSetupFailed: If `project_id` or `user_id` are missing
        from the `auth_provider` attribute in `test_obj`.
    """

    try:
        project_id = test_obj.os_primary.credentials.project_id
        user_id = test_obj.os_primary.credentials.user_id
    except AttributeError as e:
        msg = ("{0}: project_id or user_id not found in os_primary.credentials"
               .format(e))
        LOG.error(msg)
        raise rbac_exceptions.RbacResourceSetupFailed(msg)

    role = CONF.patrole.rbac_test_role
    # Test RBAC against custom requirements. Otherwise use oslo.policy.
    if CONF.patrole.test_custom_requirements:
        authority = requirements_authority.RequirementsAuthority(
            CONF.patrole.custom_requirements_file, service)
    else:
        formatted_target_data = _format_extra_target_data(
            test_obj, extra_target_data)
        authority = policy_authority.PolicyAuthority(
            project_id, user_id, service,
            extra_target_data=formatted_target_data)
    is_allowed = authority.allowed(rule, role)

    if is_allowed:
        LOG.debug("[Policy action]: %s, [Role]: %s is allowed!", rule,
                  role)
    else:
        LOG.debug("[Policy action]: %s, [Role]: %s is NOT allowed!",
                  rule, role)

    return is_allowed


def _get_exception_type(expected_error_code=_DEFAULT_ERROR_CODE):
    """Dynamically calculate the expected exception to be caught.

    Dynamically calculate the expected exception to be caught by the test case.
    Only ``Forbidden`` and ``NotFound`` exceptions are permitted. ``NotFound``
    is supported because Neutron, for security reasons, masks ``Forbidden``
    exceptions as ``NotFound`` exceptions.

    :param expected_error_code: the integer representation of the expected
        exception to be caught. Must be contained in
        ``_SUPPORTED_ERROR_CODES``.
    :returns: tuple of the exception type corresponding to
        ``expected_error_code`` and a message explaining that a non-Forbidden
        exception was expected, if applicable.
    """
    expected_exception = None
    irregular_msg = None

    if not isinstance(expected_error_code, six.integer_types) \
            or expected_error_code not in _SUPPORTED_ERROR_CODES:
        msg = ("Please pass an expected error code. Currently "
               "supported codes: {0}".format(_SUPPORTED_ERROR_CODES))
        LOG.error(msg)
        raise rbac_exceptions.RbacInvalidErrorCode(msg)

    if expected_error_code == 403:
        expected_exception = lib_exc.Forbidden
    elif expected_error_code == 404:
        expected_exception = lib_exc.NotFound
        irregular_msg = ("NotFound exception was caught for test %s. Expected "
                         "policies which may have caused the error: %s. The "
                         "service %s throws a 404 instead of a 403, which is "
                         "irregular")
    return expected_exception, irregular_msg


def _format_extra_target_data(test_obj, extra_target_data):
    """Formats the "extra_target_data" dictionary with correct test data.

    Before being formatted, "extra_target_data" is a dictionary that maps a
    policy string like "trust.trustor_user_id" to a nested list of
    ``tempest.test.BaseTestCase`` attributes. For example, the attribute list
    in::

      "trust.trustor_user_id": "os.auth_provider.credentials.user_id"

    is parsed by iteratively calling ``getattr`` until the value of "user_id"
    is resolved. The resulting dictionary returns::

      "trust.trustor_user_id": "the user_id of the `os_primary` credential"

    :param test_obj: An instance or subclass of ``tempest.test.BaseTestCase``.
    :param extra_target_data: Dictionary, keyed with ``oslo.policy`` generic
        check names, whose values are string literals that reference nested
        ``tempest.test.BaseTestCase`` attributes. Used by ``oslo.policy`` for
        performing matching against attributes that are sent along with the API
        calls.
    :returns: Dictionary containing additional object data needed by
        ``oslo.policy`` to validate generic checks.
    """
    attr_value = test_obj
    formatted_target_data = {}

    for user_attribute, attr_string in extra_target_data.items():
        attrs = attr_string.split('.')
        for attr in attrs:
            attr_value = getattr(attr_value, attr)
        formatted_target_data[user_attribute] = attr_value

    return formatted_target_data


def _check_for_expected_mismatch_exception(expected_exception,
                                           actual_exception):
    """Checks that ``expected_exception`` matches ``actual_exception``.

    Since Patrole must handle 403/404 it is important that the expected and
    actual error codes match.

    :param excepted_exception: Expected exception for test.
    :param actual_exception: Actual exception raised by test.
    :returns: True if match, else False.
    :rtype: boolean
    """
    permission_exceptions = (lib_exc.Forbidden, lib_exc.NotFound)
    if isinstance(actual_exception, permission_exceptions):
        if not isinstance(actual_exception, expected_exception.__class__):
            return True
    return False


def _validate_override_role_called(test_obj, actual_exception):
    """Validates that :func:`rbac_utils.RbacUtils.override_role` is called
    during each Patrole test.

    Useful for validating that the expected exception isn't raised too early
    (before ``override_role`` call) or too late (after ``override_call``) or
    at all (which is a bad test).

    :param test_obj: An instance or subclass of ``tempest.test.BaseTestCase``.
    :param actual_exception: Actual exception raised by test.
    :raises RbacOverrideRoleException: If ``override_role`` isn't called, is
        called too early, or is called too late.
    """
    called = test_obj._validate_override_role_called()
    base_msg = ('This error is unrelated to RBAC and is due to either '
                'an API or override role failure. Exception: %s' %
                actual_exception)

    if not called:
        if actual_exception is not None:
            msg = ('Caught exception (%s) but it was raised before the '
                   '`override_role` context. ' % actual_exception.__class__)
        else:
            msg = 'Test missing required `override_role` call. '
        msg += base_msg
        LOG.error(msg)
        raise rbac_exceptions.RbacOverrideRoleException(msg)
    else:
        exc_caught_in_ctx = test_obj._validate_override_role_caught_exc()
        # This block is only executed if ``override_role`` is called. If
        # an exception is raised and the exception wasn't raised in the
        # ``override_role`` context and if the exception isn't a valid
        # exception type (instance of ``BasePatroleException``), then this is
        # a legitimate error.
        if (not exc_caught_in_ctx and
            actual_exception is not None and
            not isinstance(actual_exception,
                           rbac_exceptions.BasePatroleException)):
            msg = ('Caught exception (%s) but it was raised after the '
                   '`override_role` context. ' % actual_exception.__class__)
            msg += base_msg
            LOG.error(msg)
            raise rbac_exceptions.RbacOverrideRoleException(msg)
