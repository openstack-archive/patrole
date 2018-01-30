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

import logging
import sys
import testtools

from oslo_utils import excutils
import six

from tempest import config
from tempest.lib import exceptions
from tempest import test

from patrole_tempest_plugin import policy_authority
from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils
from patrole_tempest_plugin import requirements_authority

CONF = config.CONF
LOG = logging.getLogger(__name__)

_SUPPORTED_ERROR_CODES = [403, 404]

RBACLOG = logging.getLogger('rbac_reporting')


def action(service, rule='', admin_only=False, expected_error_code=403,
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
       `Forbidden` exception failure.
    3) If *expected* is False and the test passes (*actual*), this results in
       an `OverPermission` exception failure.
    4) If *expected* is False and the test fails (*actual*), this is a success.

    As such, negative and positive testing can be applied using this decorator.

    :param service: An OpenStack service. Examples: "nova" or "neutron".
    :param rule: A policy action defined in a policy.json file (or in
        code).

        .. note::

            Patrole currently only supports custom JSON policy files.

    :param admin_only: Skips over ``oslo.policy`` check because the policy
        action defined by ``rule`` is not enforced by the service's policy
        enforcement engine. For example, Keystone v2 performs an admin check
        for most of its endpoints. If True, ``rule`` is effectively ignored.
    :param expected_error_code: Overrides default value of 403 (Forbidden)
        with endpoint-specific error code. Currently only supports 403 and 404.
        Support for 404 is needed because some services, like Neutron,
        intentionally throw a 404 for security reasons.

        .. warning::

            A 404 should not be provided *unless* the endpoint masks a
            ``Forbidden`` exception as a ``NotFound`` exception.

    :param extra_target_data: Dictionary, keyed with ``oslo.policy`` generic
        check names, whose values are string literals that reference nested
        ``tempest.test.BaseTestCase`` attributes. Used by ``oslo.policy`` for
        performing matching against attributes that are sent along with the API
        calls. Example::

            extra_target_data={
                "target.token.user_id":
                "os_alt.auth_provider.credentials.user_id"
            })

    :raises NotFound: If ``service`` is invalid.
    :raises Forbidden: For item (2) above.
    :raises RbacOverPermission: For item (3) above.

    Examples::

        @rbac_rule_validation.action(
            service="nova", rule="os_compute_api:os-agents")
        def test_list_agents_rbac(self):
            # The call to `switch_role` is mandatory.
            self.rbac_utils.switch_role(self, toggle_rbac_role=True)
            self.agents_client.list_agents()
    """

    if extra_target_data is None:
        extra_target_data = {}

    def decorator(test_func):
        role = CONF.patrole.rbac_test_role

        def wrapper(*args, **kwargs):
            if args and isinstance(args[0], test.BaseTestCase):
                test_obj = args[0]
            else:
                raise rbac_exceptions.RbacResourceSetupFailed(
                    '`rbac_rule_validation` decorator can only be applied to '
                    'an instance of `tempest.test.BaseTestCase`.')

            allowed = _is_authorized(test_obj, service, rule,
                                     extra_target_data, admin_only)

            expected_exception, irregular_msg = _get_exception_type(
                expected_error_code)

            test_status = 'Allowed'

            try:
                test_func(*args, **kwargs)
            except rbac_exceptions.RbacInvalidService as e:
                msg = ("%s is not a valid service." % service)
                test_status = ('Error, %s' % (msg))
                LOG.error(msg)
                raise exceptions.NotFound(
                    "%s RbacInvalidService was: %s" % (msg, e))
            except (expected_exception,
                    rbac_exceptions.RbacConflictingPolicies,
                    rbac_exceptions.RbacMalformedResponse) as e:
                test_status = 'Denied'
                if irregular_msg:
                    LOG.warning(irregular_msg.format(rule, service))
                if allowed:
                    msg = ("Role %s was not allowed to perform %s." %
                           (role, rule))
                    LOG.error(msg)
                    raise exceptions.Forbidden(
                        "%s Exception was: %s" % (msg, e))
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    exc_info = sys.exc_info()
                    error_details = six.text_type(exc_info[1])
                    msg = ("An unexpected exception has occurred during test: "
                           "%s. Exception was: %s" % (test_func.__name__,
                                                      error_details))
                    test_status = 'Error, %s' % (error_details)
                    LOG.error(msg)
            else:
                if not allowed:
                    LOG.error("Role %s was allowed to perform %s",
                              role, rule)
                    raise rbac_exceptions.RbacOverPermission(
                        "OverPermission: Role %s was allowed to perform %s" %
                        (role, rule))
            finally:
                if CONF.patrole_log.enable_reporting:
                    RBACLOG.info(
                        "[Service]: %s, [Test]: %s, [Rule]: %s, "
                        "[Expected]: %s, [Actual]: %s",
                        service, test_func.__name__, rule,
                        "Allowed" if allowed else "Denied",
                        test_status)

        _wrapper = testtools.testcase.attr(role)(wrapper)
        return _wrapper
    return decorator


def _is_authorized(test_obj, service, rule, extra_target_data, admin_only):
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
    :param admin_only: Skips over ``oslo.policy`` check because the policy
        action defined by ``rule`` is not enforced by the service's policy
        enforcement engine. For example, Keystone v2 performs an admin check
        for most of its endpoints. If True, ``rule`` is effectively ignored.

    :returns: True if the current RBAC role can perform the policy action,
        else False.

    :raises RbacResourceSetupFailed: If `project_id` or `user_id` are missing
        from the `auth_provider` attribute in `test_obj`.
    :raises RbacParsingException: if ``[patrole] strict_policy_check`` is True
        and the ``rule`` does not exist in the system.
    :raises skipException: If ``[patrole] strict_policy_check`` is False and
        the ``rule`` does not exist in the system.
    """

    if admin_only:
        LOG.info("As admin_only is True, only admin role should be "
                 "allowed to perform the API. Skipping oslo.policy "
                 "check for policy action {0}.".format(rule))
        return rbac_utils.is_admin()

    try:
        project_id = test_obj.os_primary.credentials.project_id
        user_id = test_obj.os_primary.credentials.user_id
    except AttributeError as e:
        msg = ("{0}: project_id or user_id not found in os_primary.credentials"
               .format(e))
        LOG.error(msg)
        raise rbac_exceptions.RbacResourceSetupFailed(msg)

    try:
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
            LOG.debug("[Action]: %s, [Role]: %s is allowed!", rule,
                      role)
        else:
            LOG.debug("[Action]: %s, [Role]: %s is NOT allowed!",
                      rule, role)
        return is_allowed
    except rbac_exceptions.RbacParsingException as e:
        if CONF.patrole.strict_policy_check:
            raise e
        else:
            raise testtools.TestCase.skipException(str(e))
    return False


def _get_exception_type(expected_error_code=403):
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
        expected_exception = exceptions.Forbidden
    elif expected_error_code == 404:
        expected_exception = exceptions.NotFound
        irregular_msg = ("NotFound exception was caught for policy action "
                         "{0}. The service {1} throws a 404 instead of a 403, "
                         "which is irregular.")

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
