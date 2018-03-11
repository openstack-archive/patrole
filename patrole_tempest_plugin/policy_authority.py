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
import json
import os

from oslo_log import log as logging
from oslo_policy import policy
import stevedore
from tempest import clients
from tempest.common import credentials_factory as credentials
from tempest import config

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin.rbac_utils import RbacAuthority

CONF = config.CONF
LOG = logging.getLogger(__name__)


class PolicyAuthority(RbacAuthority):
    """A class that uses ``oslo.policy`` for validating RBAC."""

    def __init__(self, project_id, user_id, service, extra_target_data=None):
        """Initialization of Policy Authority class.

        Validates whether a test role can perform a policy action by querying
        ``oslo.policy`` with necessary test data.

        If a policy file does not exist, checks whether the policy file is
        registered as a namespace under "oslo.policy.policies". Nova, for
        example, doesn't use a policy file by default; its policies are
        implemented in code and registered as "nova" under
        "oslo.policy.policies".

        If the policy file is not found in either code or in a policy file,
        then an exception is raised.

        Additionally, if a custom policy file exists along with the default
        policy in code implementation, the custom policy is prioritized.

        :param uuid project_id: project_id of object performing API call
        :param uuid user_id: user_id of object performing API call
        :param string service: service of the policy file
        :param dict extra_target_data: dictionary containing additional object
            data needed by oslo.policy to validate generic checks

        Example:

        .. code-block:: python

            # Below is the default policy implementation in code, defined in
            # a service like Nova.
            test_policies = [
                policy.DocumentedRuleDefault(
                    'service:test_rule',
                    base.RULE_ADMIN_OR_OWNER,
                    "This is a description for a test policy",
                    [
                        {
                            'method': 'POST',
                            'path': '/path/to/test/resource'
                        }
                    ]),
                    'service:another_test_rule',
                    base.RULE_ADMIN_OR_OWNER,
                    "This is a description for another test policy",
                    [
                        {
                            'method': 'GET',
                            'path': '/path/to/test/resource'
                        }
                    ]),
            ]

        .. code-block:: yaml

            # Below is the custom override of the default policy in a YAML
            # policy file. Note that the default rule is "rule:admin_or_owner"
            # and the custom rule is "rule:admin_api". The `PolicyAuthority`
            # class will use the "rule:admin_api" definition for this policy
            # action.
            "service:test_rule" : "rule:admin_api"

            # Note below that no override is provided for
            # "service:another_test_rule", which means that the default policy
            # rule is used: "rule:admin_or_owner".
        """

        if extra_target_data is None:
            extra_target_data = {}

        self.validate_service(service)

        # Prioritize dynamically searching for policy files over relying on
        # deprecated service-specific policy file locations.
        self.path = None
        if CONF.patrole.custom_policy_files:
            self.discover_policy_files()
            self.path = self.policy_files.get(service)

        self.rules = policy.Rules.load(self._get_policy_data(service),
                                       'default')
        self.project_id = project_id
        self.user_id = user_id
        self.extra_target_data = extra_target_data

    @classmethod
    def validate_service(cls, service):
        """Validate whether the service passed to ``__init__`` exists."""
        service = service.lower().strip() if service else None

        # Cache the list of available services in memory to avoid needlessly
        # doing an API call every time.
        if not hasattr(cls, 'available_services'):
            admin_mgr = clients.Manager(
                credentials.get_configured_admin_credentials())
            services_client = (admin_mgr.identity_services_v3_client
                               if CONF.identity_feature_enabled.api_v3
                               else admin_mgr.identity_services_client)
            services = services_client.list_services()['services']
            cls.available_services = [s['name'] for s in services]

        if not service or service not in cls.available_services:
            LOG.debug("%s is NOT a valid service.", service)
            raise rbac_exceptions.RbacInvalidService(
                "%s is NOT a valid service." % service)

    @classmethod
    def discover_policy_files(cls):
        """Dynamically discover the policy file for each service in
        ``cls.available_services``. Pick the first candidate path found
        out of the potential paths in ``[patrole] custom_policy_files``.
        """
        if not hasattr(cls, 'policy_files'):
            cls.policy_files = {}
            for service in cls.available_services:
                for candidate_path in CONF.patrole.custom_policy_files:
                    if os.path.isfile(candidate_path % service):
                        cls.policy_files.setdefault(service,
                                                    candidate_path % service)

    def allowed(self, rule_name, role):
        """Checks if a given rule in a policy is allowed with given role.

        :param string rule_name: Rule to be checked using ``oslo.policy``.
        :param bool is_admin: Whether admin context is used.
        :raises RbacParsingException: If `rule_name`` does not exist in the
            cloud (in policy file or among registered in-code policy defaults).
        """
        is_admin_context = self._is_admin_context(role)
        is_allowed = self._allowed(
            access=self._get_access_token(role),
            apply_rule=rule_name,
            is_admin=is_admin_context)
        return is_allowed

    def _get_policy_data(self, service):
        file_policy_data = {}
        mgr_policy_data = {}
        policy_data = {}

        # Check whether policy file exists and attempt to read it.
        if self.path and os.path.isfile(self.path):
            try:
                with open(self.path, 'r') as policy_file:
                    file_policy_data = policy_file.read()
                file_policy_data = json.loads(file_policy_data)
            except (IOError, ValueError) as e:
                msg = "Failed to read policy file for service. "
                if isinstance(e, IOError):
                    msg += "Please check that policy path exists."
                else:
                    msg += "JSON may be improperly formatted."
                LOG.debug(msg)
                file_policy_data = {}

        # Check whether policy actions are defined in code. Nova and Keystone,
        # for example, define their default policy actions in code.
        mgr = stevedore.named.NamedExtensionManager(
            'oslo.policy.policies',
            names=[service],
            on_load_failure_callback=None,
            invoke_on_load=True,
            warn_on_missing_entrypoint=False)

        if mgr:
            policy_generator = {policy.name: policy.obj for policy in mgr}
            if policy_generator and service in policy_generator:
                for rule in policy_generator[service]:
                    mgr_policy_data[rule.name] = str(rule.check)

        # If data from both file and code exist, combine both together.
        if file_policy_data and mgr_policy_data:
            # Add the policy actions from code first.
            for action, rule in mgr_policy_data.items():
                policy_data[action] = rule
            # Overwrite with any custom policy actions defined in policy.json.
            for action, rule in file_policy_data.items():
                policy_data[action] = rule
        elif file_policy_data:
            policy_data = file_policy_data
        elif mgr_policy_data:
            policy_data = mgr_policy_data
        else:
            error_message = (
                'Policy file for {0} service was not found among the '
                'registered in-code policies or in any of the possible policy '
                'files: {1}.'.format(service,
                                     [loc % service for loc in
                                      CONF.patrole.custom_policy_files])
            )
            raise rbac_exceptions.RbacParsingException(error_message)

        try:
            policy_data = json.dumps(policy_data)
        except (TypeError, ValueError):
            error_message = 'Policy file for {0} service is invalid.'.format(
                service)
            raise rbac_exceptions.RbacParsingException(error_message)

        return policy_data

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
        return role == CONF.identity.admin_role

    def _get_access_token(self, role):
        access_token = {
            "token": {
                "roles": [
                    {
                        "name": role
                    }
                ],
                "project_id": self.project_id,
                "tenant_id": self.project_id,
                "user_id": self.user_id
            }
        }
        return access_token

    def _allowed(self, access, apply_rule, is_admin=False):
        """Checks if a given rule in a policy is allowed with given ``access``.

        :param dict access: Dictionary from ``_get_access_token``.
        :param string apply_rule: Rule to be checked using ``oslo.policy``.
        :param bool is_admin: Whether admin context is used.
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
        if self.extra_target_data:
            target.update(self.extra_target_data)

        result = self._try_rule(apply_rule, target, access_data, o)
        return result

    def _try_rule(self, apply_rule, target, access_data, o):
        if apply_rule not in self.rules:
            message = ("Policy action \"{0}\" not found in policy file: {1} or"
                       " among registered policy in code defaults for service."
                       ).format(apply_rule, self.path)
            LOG.debug(message)
            raise rbac_exceptions.RbacParsingException(message)
        else:
            rule = self.rules[apply_rule]
            return rule(target, access_data, o)
