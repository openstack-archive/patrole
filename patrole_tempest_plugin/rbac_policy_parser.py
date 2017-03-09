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
from oslo_policy import generator
from oslo_policy import policy

from tempest.common import credentials_factory as credentials

from patrole_tempest_plugin import rbac_exceptions

LOG = logging.getLogger(__name__)


class RbacPolicyParser(object):
    """A class for parsing policy rules into lists of allowed roles.

    RBAC testing requires that each rule in a policy file be broken up into
    the roles that constitute it. This class automates that process.

    The list of roles per rule can be reverse-engineered by checking, for
    each role, whether a given rule is allowed using oslo policy.
    """

    def __init__(self, tenant_id, user_id, service=None, path=None):
        """Initialization of Rbac Policy Parser.

        Parses a policy file to create a dictionary, mapping policy actions to
        roles. If a policy file does not exist, checks whether the policy file
        is registered as a namespace under oslo.policy.policies. Nova, for
        example, doesn't use a policy.json file by default; its policy is
        implemented in code and registered as 'nova' under
        oslo.policy.policies.

        If the policy file is not found in either place, raises an exception.

        Additionally, if the policy file exists in both code and as a
        policy.json (for example, by creating a custom nova policy.json file),
        the custom policy file over the default policy implementation is
        prioritized.

        :param tenant_id: type uuid
        :param user_id: type uuid
        :param service: type string
        :param path: type string
        """
        # First check if the service is valid
        service = service.lower().strip() if service else None
        self.admin_mgr = credentials.AdminManager()
        services = self.admin_mgr.identity_services_v3_client.\
            list_services()['services']
        service_names = [s['name'] for s in services]
        if not service or not any(service in name for name in service_names):
            LOG.debug(str(service) + " is NOT a valid service.")
            raise rbac_exceptions.RbacInvalidService

        # Use default path if no path provided
        if path is None:
            self.path = os.path.join('/etc', service, 'policy.json')
        else:
            self.path = path

        policy_data = "{}"

        # Check whether policy file exists.
        if os.path.isfile(self.path):
            policy_data = open(self.path, 'r').read()
        # Otherwise use oslo_policy to fetch the rules for provided service.
        else:
            policy_generator = generator._get_policies_dict([service])
            if policy_generator and service in policy_generator:
                policy_data = "{\n"
                for r in policy_generator[service]:
                    policy_data = policy_data + r.__str__() + ",\n"
                policy_data = policy_data[:-2] + "\n}"
            # Otherwise raise an exception.
            else:
                raise rbac_exceptions.RbacResourceSetupFailed(
                    'Policy file for service: {0}, {1} not found.'
                    .format(service, self.path))

        self.rules = policy.Rules.load(policy_data, "default")
        self.tenant_id = tenant_id
        self.user_id = user_id

    def allowed(self, rule_name, role):
        is_admin_context = self._is_admin_context(role)
        is_allowed = self._allowed(
            access=self._get_access_token(role),
            apply_rule=rule_name,
            is_admin=is_admin_context)

        return is_allowed

    def _is_admin_context(self, role):
        """Checks whether a role has admin context.

        If context_is_admin is contained in the policy file, then checks
        whether the given role is contained in context_is_admin. If it is not
        in the policy file, then default to context_is_admin: admin.
        """
        if 'context_is_admin' in self.rules.keys():
            return self._allowed(
                access=self._get_access_token(role),
                apply_rule='context_is_admin')
        return role == 'admin'

    def _get_access_token(self, role):
        access_token = {
            "token": {
                "roles": [
                    {
                        "name": role
                    }
                ],
                "project_id": self.tenant_id,
                "tenant_id": self.tenant_id,
                "user_id": self.user_id
            }
        }
        return access_token

    def _allowed(self, access, apply_rule, is_admin=False):
        """Checks if a given rule in a policy is allowed with given access.

        Adapted from oslo_policy.shell.

        :param access: type dict: dictionary from ``_get_access_token``
        :param apply_rule: type string: rule to be checked
        :param is_admin: type bool: whether admin context is used
        """
        access_data = copy.copy(access['token'])
        access_data['roles'] = [role['name'] for role in access_data['roles']]
        access_data['is_admin'] = is_admin
        # TODO(felipemonteiro): Dynamically calculate is_admin_project rather
        # than hard-coding it to True. is_admin_project cannot be determined
        # from the role, but rather from project and domain names. See
        # _populate_is_admin_project in keystone.token.providers.common
        # for more information.
        access_data['is_admin_project'] = True

        class Object(object):
            pass
        o = Object()
        o.rules = self.rules

        target = {"project_id": access_data['project_id'],
                  "tenant_id": access_data['project_id'],
                  "network:tenant_id": access_data['project_id'],
                  "user_id": access_data['user_id']}

        result = self._try_rule(apply_rule, target, access_data, o)
        return result

    def _try_rule(self, apply_rule, target, access_data, o):
        try:
            rule = self.rules[apply_rule]
            return rule(target, access_data, o)
        except KeyError as e:
            LOG.debug("{0} not found in policy file.".format(apply_rule))
            return False
        except Exception as e:
            LOG.debug("Exception: {0} for rule: {1}.".format(e, apply_rule))
            return False
