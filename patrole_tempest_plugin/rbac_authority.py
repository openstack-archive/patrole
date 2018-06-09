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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class RbacAuthority(object):
    """Class for validating whether a given role can perform a policy action.

    Any class that extends ``RbacAuthority`` provides the logic for determining
    whether a role has permissions to execute a policy action.
    """

    @abc.abstractmethod
    def allowed(self, rule, role):
        """Determine whether the role should be able to perform the API.

        :param rule: The name of the policy enforced by the API.
        :param role: The role used to determine whether ``rule`` can be
            executed.
        :returns: True if the ``role`` has permissions to execute
            ``rule``, else False.
        """
