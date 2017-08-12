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


class RbacConflictingPolicies(exceptions.TempestException):
    message = ("Conflicting policies preventing this action from being "
               "performed.")


class RbacMalformedResponse(exceptions.TempestException):
    message = ("The response body is missing the expected %(attribute)s due "
               "to policy enforcement failure.")

    def __init__(self, empty=False, extra_attr=False, **kwargs):
        if empty:
            self.message = ("The response body is empty due to policy "
                            "enforcement failure.")
            kwargs = {}
        if extra_attr:
            self.message = ("The response body contained an unexpected "
                            "attribute due to policy enforcement failure.")
            kwargs = {}
        super(RbacMalformedResponse, self).__init__(**kwargs)


class RbacResourceSetupFailed(exceptions.TempestException):
    message = "Rbac resource setup failed"


class RbacOverPermission(exceptions.TempestException):
    message = "Action performed that should not be permitted"


class RbacInvalidService(exceptions.TempestException):
    message = "Attempted to test an invalid service"


class RbacParsingException(exceptions.TempestException):
    message = "Attempted to test an invalid policy file or action"


class RbacInvalidErrorCode(exceptions.TempestException):
    message = "Unsupported error code passed in test"
