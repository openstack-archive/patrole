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

import six

from tempest import config
from tempest.lib import exceptions
from tempest import test

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_policy_parser

CONF = config.CONF
LOG = logging.getLogger(__name__)


def action(service, rule='', admin_only=False, expected_error_code=403,
           extra_target_data=None):
    """A decorator which does a policy check and matches it against test run.

    A decorator which allows for positive and negative RBAC testing. Given
    an OpenStack service and a policy action enforced by that service, an
    oslo.policy lookup is performed by calling `authority.get_permission`.
    The following cases are possible:

    * If `allowed` is True and the test passes, this is a success.
    * If `allowed` is True and the test fails, this is a failure.
    * If `allowed` is False and the test passes, this is a failure.
    * If `allowed` is False and the test fails, this is a success.

    :param service: A OpenStack service: for example, "nova" or "neutron".
    :param rule: A policy action defined in a policy.json file (or in code).
    :param admin_only: Skips over oslo.policy check because the policy action
                       defined by `rule` is not enforced by the service's
                       policy enforcement logic. For example, Keystone v2
                       performs an admin check for most of its endpoints. If
                       True, `rule` is effectively ignored.
    :param expected_error_code: Overrides default value of 403 (Forbidden)
                                with endpoint-specific error code. Currently
                                only supports 403 and 404. Support for 404
                                is needed because some services, like Neutron,
                                intentionally throw a 404 for security reasons.

    :raises NotFound: if `service` is invalid or
                      if Tempest credentials cannot be found.
    :raises Forbidden: for bullet (2) above.
    :raises RbacOverPermission: for bullet (3) above.
    """

    if extra_target_data is None:
        extra_target_data = {}

    def decorator(func):
        role = CONF.rbac.rbac_test_role

        def wrapper(*args, **kwargs):
            if args and isinstance(args[0], test.BaseTestCase):
                test_obj = args[0]
            else:
                raise rbac_exceptions.RbacResourceSetupFailed(
                    '`rbac_rule_validation` decorator can only be applied to '
                    'an instance of `tempest.test.BaseTestCase`.')

            if admin_only:
                LOG.info("As admin_only is True, only admin role should be "
                         "allowed to perform the API. Skipping oslo.policy "
                         "check for policy action {0}.".format(rule))
                allowed = CONF.rbac.rbac_test_role == CONF.identity.admin_role
            else:
                allowed = _is_authorized(test_obj, service, rule,
                                         extra_target_data)

            expected_exception, irregular_msg = _get_exception_type(
                expected_error_code)

            try:
                func(*args, **kwargs)
            except rbac_exceptions.RbacInvalidService as e:
                msg = ("%s is not a valid service." % service)
                LOG.error(msg)
                raise exceptions.NotFound(
                    "%s RbacInvalidService was: %s" % (msg, e))
            except (expected_exception, rbac_exceptions.RbacActionFailed) as e:
                if irregular_msg:
                    LOG.warning(irregular_msg.format(rule, service))
                if allowed:
                    msg = ("Role %s was not allowed to perform %s." %
                           (role, rule))
                    LOG.error(msg)
                    raise exceptions.Forbidden(
                        "%s Exception was: %s" % (msg, e))
            except Exception as e:
                exc_info = sys.exc_info()
                error_details = exc_info[1].__str__()
                msg = ("%s An unexpected exception has occurred: Expected "
                       "exception was %s, which was not thrown."
                       % (error_details, expected_exception.__name__))
                LOG.error(msg)
                six.reraise(exc_info[0], exc_info[0](msg), exc_info[2])
            else:
                if not allowed:
                    LOG.error("Role %s was allowed to perform %s",
                              role, rule)
                    raise rbac_exceptions.RbacOverPermission(
                        "OverPermission: Role %s was allowed to perform %s" %
                        (role, rule))
            finally:
                test_obj.rbac_utils.switch_role(test_obj,
                                                toggle_rbac_role=False)

        _wrapper = testtools.testcase.attr(role)(wrapper)
        return _wrapper
    return decorator


def _is_authorized(test_obj, service, rule_name, extra_target_data):
    try:
        project_id = test_obj.auth_provider.credentials.project_id
        user_id = test_obj.auth_provider.credentials.user_id
    except AttributeError as e:
        msg = ("{0}: project_id/user_id not found in "
               "cls.auth_provider.credentials".format(e))
        LOG.error(msg)
        raise rbac_exceptions.RbacResourceSetupFailed(msg)

    try:
        role = CONF.rbac.rbac_test_role
        formatted_target_data = _format_extra_target_data(
            test_obj, extra_target_data)
        policy_parser = rbac_policy_parser.RbacPolicyParser(
            project_id, user_id, service,
            extra_target_data=formatted_target_data)
        is_allowed = policy_parser.allowed(rule_name, role)

        if is_allowed:
            LOG.debug("[Action]: %s, [Role]: %s is allowed!", rule_name,
                      role)
        else:
            LOG.debug("[Action]: %s, [Role]: %s is NOT allowed!",
                      rule_name, role)
        return is_allowed
    except rbac_exceptions.RbacParsingException as e:
        if CONF.rbac.strict_policy_check:
            raise e
        else:
            raise testtools.TestCase.skipException(str(e))
    return False


def _get_exception_type(expected_error_code):
    expected_exception = None
    irregular_msg = None
    supported_error_codes = [403, 404]

    if expected_error_code == 403:
        expected_exception = exceptions.Forbidden
    elif expected_error_code == 404:
        expected_exception = exceptions.NotFound
        irregular_msg = ("NotFound exception was caught for policy action "
                         "{0}. The service {1} throws a 404 instead of a 403, "
                         "which is irregular.")
    else:
        msg = ("Please pass an expected error code. Currently "
               "supported codes: {0}".format(str(supported_error_codes)))
        LOG.error(msg)
        raise rbac_exceptions.RbacInvalidErrorCode()

    return expected_exception, irregular_msg


def _format_extra_target_data(test_obj, extra_target_data):
    """Formats the "extra_target_data" dictionary with correct test data.

    Before being formatted, "extra_target_data" is a dictionary that maps a
    policy string like "trust.trustor_user_id" to a nested list of BaseTestCase
    attributes. For example, the attribute list in:

        "trust.trustor_user_id": "os.auth_provider.credentials.user_id"

    is parsed by iteratively calling `getattr` until the value of "user_id"
    is resolved. The resulting dictionary returns:

        "trust.trustor_user_id": "the user_id of the `primary` credential"

    :param test_obj: type BaseTestCase (tempest base test class)
    :param extra_target_data: dictionary with unresolved string literals that
                              reference nested BaseTestCase attributes
    :returns: dictionary with resolved BaseTestCase attributes
    """
    attr_value = test_obj
    formatted_target_data = {}

    for user_attribute, attr_string in extra_target_data.items():
        attrs = attr_string.split('.')
        for attr in attrs:
            attr_value = getattr(attr_value, attr)
        formatted_target_data[user_attribute] = attr_value

    return formatted_target_data
