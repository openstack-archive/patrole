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

from tempest.lib import exceptions


class BasePatroleException(exceptions.TempestException):
    message = "An unknown RBAC exception occurred"


class BasePatroleResponseBodyException(BasePatroleException):
    message = "Response body incomplete due to RBAC authorization failure"


class RbacMissingAttributeResponseBody(BasePatroleResponseBodyException):
    """Raised when a list or show action is missing an attribute following
    RBAC authorization failure.
    """
    message = ("The response body is missing the expected %(attribute)s due "
               "to policy enforcement failure")


class RbacPartialResponseBody(BasePatroleResponseBodyException):
    """Raised when a list action only returns a subset of the available
    resources.

    For example, admin can return more resources than member for a list action.
    """
    message = ("The response body only lists a subset of the available "
               "resources due to partial policy enforcement failure. Response "
               "body: %(body)s")


class RbacEmptyResponseBody(BasePatroleResponseBodyException):
    """Raised when a list or show action is empty following RBAC authorization
    failure.
    """
    message = ("The response body is empty due to policy enforcement failure.")


class RbacResourceSetupFailed(BasePatroleException):
    message = "RBAC resource setup failed"


class RbacOverPermissionException(BasePatroleException):
    """Raised when the expected result is failure but the actual result is
    pass.
    """
    message = "Unauthorized action was allowed to be performed"


class RbacUnderPermissionException(BasePatroleException):
    """Raised when the expected result is pass but the actual result is
    failure.
    """
    message = "Authorized action was not allowed to be performed"


class RbacExpectedWrongException(BasePatroleException):
    """Raised when the expected exception does not match the actual exception
    raised, when both are instances of Forbidden or NotFound, indicating
    the test provides a wrong argument to `expected_error_codes`.
    """
    message = ("Expected %(expected)s to be raised but %(actual)s was raised "
               "instead. Actual exception: %(exception)s")


class RbacInvalidServiceException(BasePatroleException):
    """Raised when an invalid service is passed to ``rbac_rule_validation``
    decorator.
    """
    message = "Attempted to test an invalid service"


class RbacParsingException(BasePatroleException):
    message = "Attempted to test an invalid policy file or action"


class RbacInvalidErrorCode(BasePatroleException):
    message = "Unsupported error code passed in test"


class RbacOverrideRoleException(BasePatroleException):
    """Raised when override_role is used incorrectly or fails somehow.

    Used for safeguarding against false positives that might occur when the
    expected exception isn't raised inside the ``override_role`` context.
    Specifically, when:

    * ``override_role`` isn't called
    * an exception is raised before ``override_role`` context
    * an exception is raised after ``override_role`` context
    """
    message = "Override role failure or incorrect usage"
