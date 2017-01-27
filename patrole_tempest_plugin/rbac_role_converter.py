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

import copy
import os

from oslo_log import log as logging
from oslo_policy import policy
from tempest import config

from patrole_tempest_plugin import rbac_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacPolicyConverter(object):
    """A class for parsing policy rules into lists of allowed roles.

    RBAC testing requires that each rule in a policy file be broken up into
    the roles that constitute it. This class automates that process.

    The list of roles per rule can be reverse-engineered by checking, for
    each role, whether a given rule is allowed using oslo policy.
    """

    def __init__(self, tenant_id, service, path=None):
        """Initialization of Policy Converter.

        Parse policy files to create dictionary mapping policy actions to
        roles.

        :param tenant_id: type uuid
        :param service: type string
        :param path: type string
        """
        if path is None:
            self.path = '/etc/{0}/policy.json'.format(service)
        else:
            self.path = path

        if not os.path.isfile(self.path):
            raise rbac_exceptions.RbacResourceSetupFailed(
                'Policy file for service: {0}, {1} not found.'
                .format(service, self.path))

        self.tenant_id = tenant_id

    def allowed(self, rule_name, role):
        policy_file = open(self.path, 'r')
        access_token = self._get_access_token(role)

        is_allowed = self._allowed(
            policy_file=policy_file,
            access=access_token,
            apply_rule=rule_name,
            is_admin=False)

        policy_file = open(self.path, 'r')
        access_token = self._get_access_token(role)
        allowed_as_admin_context = self._allowed(
            policy_file=policy_file,
            access=access_token,
            apply_rule=rule_name,
            is_admin=True)

        if allowed_as_admin_context and is_allowed:
            return True
        if allowed_as_admin_context and not is_allowed:
            return False
        if not allowed_as_admin_context and is_allowed:
            return True
        if not allowed_as_admin_context and not is_allowed:
            return False

    def _get_access_token(self, role):
        access_token = {
            "token": {
                "roles": [
                    {
                        "name": role
                    }
                ],
                "project": {
                    "id": self.tenant_id
                }
            }
        }
        return access_token

    def _allowed(self, policy_file, access, apply_rule, is_admin=False):
        """Checks if a given rule in a policy is allowed with given access.

        Adapted from oslo_policy.shell.

        :param policy file: type string: path to policy file
        :param access: type dict: dictionary from ``_get_access_token``
        :param apply_rule: type string: rule to be checked
        :param is_admin: type bool: whether admin context is used
        """
        access_data = copy.copy(access['token'])
        access_data['roles'] = [role['name'] for role in access_data['roles']]
        access_data['project_id'] = access_data['project']['id']
        access_data['is_admin'] = is_admin
        policy_data = policy_file.read()
        rules = policy.Rules.load(policy_data, "default")

        class Object(object):
            pass
        o = Object()
        o.rules = rules

        target = {"project_id": access_data['project_id']}

        key = apply_rule
        rule = rules[apply_rule]
        result = self._try_rule(key, rule, target, access_data, o)
        return result

    def _try_rule(self, key, rule, target, access_data, o):
        try:
            return rule(target, access_data, o)
        except Exception as e:
            LOG.debug("Exception: {0} for rule: {1}".format(e, rule))
            return False
