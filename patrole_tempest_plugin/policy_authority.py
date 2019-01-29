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

import collections
import copy
import glob
import os

from oslo_log import log as logging
from oslo_policy import policy
import stevedore
from tempest import clients
from tempest.common import credentials_factory as credentials
from tempest import config

from patrole_tempest_plugin.rbac_authority import RbacAuthority
from patrole_tempest_plugin import rbac_exceptions

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

        self.service = self.validate_service(service)

        # Prioritize dynamically searching for policy files over relying on
        # deprecated service-specific policy file locations.
        if CONF.patrole.custom_policy_files:
            self.discover_policy_files()

        self.rules = self.get_rules()
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
            raise rbac_exceptions.RbacInvalidServiceException(
                "%s is NOT a valid service." % service)

        return service

    @classmethod
    def discover_policy_files(cls):
        """Dynamically discover the policy file for each service in
        ``cls.available_services``. Pick all candidate paths found
        out of the potential paths in ``[patrole] custom_policy_files``.
        """
        if not hasattr(cls, 'policy_files'):
            cls.policy_files = collections.defaultdict(list)
            for service in cls.available_services:
                for candidate_path in CONF.patrole.custom_policy_files:
                    path = candidate_path % service
                    for filename in glob.iglob(path):
                        if os.path.isfile(filename):
                            cls.policy_files[service].append(filename)

    def allowed(self, rule_name, roles):
        """Checks if a given rule in a policy is allowed with given role.

        :param string rule_name: Policy name to pass to``oslo.policy``.
        :param List[string] roles: List of roles to validate for authorization.
        :raises RbacParsingException: If ``rule_name`` does not exist in the
            cloud (in policy file or among registered in-code policy defaults).
        """
        is_admin_context = self._is_admin_context(roles)
        is_allowed = self._allowed(
            access=self._get_access_token(roles),
            apply_rule=rule_name,
            is_admin=is_admin_context)
        return is_allowed

    def _handle_deprecated_rule(self, default):
        deprecated_rule = default.deprecated_rule
        deprecated_msg = (
            'Policy "%(old_name)s":"%(old_check_str)s" was deprecated in '
            '%(release)s in favor of "%(name)s":"%(check_str)s". Reason: '
            '%(reason)s. Either ensure your deployment is ready for the new '
            'default or copy/paste the deprecated policy into your policy '
            'file and maintain it manually.' % {
                'old_name': deprecated_rule.name,
                'old_check_str': deprecated_rule.check_str,
                'release': default.deprecated_since,
                'name': default.name,
                'check_str': default.check_str,
                'reason': default.deprecated_reason
            }
        )
        LOG.warn(deprecated_msg)
        check_str = '(%s) or (%s)' % (default.check_str,
                                      deprecated_rule.check_str)
        return policy.RuleDefault(default.name, check_str)

    def get_rules(self):
        rules = policy.Rules()
        # Check whether policy file exists and attempt to read it.
        for path in self.policy_files[self.service]:
            try:
                with open(path, 'r') as fp:
                    for k, v in policy.Rules.load(fp.read()).items():
                        if k not in rules:
                            rules[k] = v
                        # If the policy name and rule are the same, no
                        # ambiguity, so no reason to warn.
                        elif str(v) != str(rules[k]):
                            msg = ("The same policy name: %s was found in "
                                   "multiple policies files for service %s. "
                                   "This can lead to policy rule ambiguity. "
                                   "Using rule: %s; Rule from file: %s")
                            LOG.warning(msg, k, self.service, rules[k], v)
            except (ValueError, IOError):
                LOG.warning("Failed to read policy file '%s' for service %s.",
                            path, self.service)

        # Check whether policy actions are defined in code. Nova and Keystone,
        # for example, define their default policy actions in code.
        mgr = stevedore.named.NamedExtensionManager(
            'oslo.policy.policies',
            names=[self.service],
            invoke_on_load=True,
            warn_on_missing_entrypoint=False)

        if mgr:
            policy_generator = {plc.name: plc.obj for plc in mgr}
            if self.service in policy_generator:
                for rule in policy_generator[self.service]:
                    if rule.name not in rules:
                        if CONF.patrole.validate_deprecated_rules:
                            # NOTE (sergey.vilgelm):
                            # The `DocumentedRuleDefault` object has no
                            # `deprecated_rule` attribute in Pike
                            if getattr(rule, 'deprecated_rule', False):
                                rule = self._handle_deprecated_rule(rule)
                        rules[rule.name] = rule.check
                    elif str(rule.check) != str(rules[rule.name]):
                        msg = ("The same policy name: %s was found in the "
                               "policies files and in the code for service "
                               "%s. This can lead to policy rule ambiguity. "
                               "Using rule: %s; Rule from code: %s")
                        LOG.warning(msg, rule.name, self.service,
                                    rules[rule.name], rule.check)

        if not rules:
            msg = (
                'Policy files for {0} service were not found among the '
                'registered in-code policies or in any of the possible policy '
                'files: {1}.'.format(
                    self.service,
                    [loc % self.service
                     for loc in CONF.patrole.custom_policy_files]))
            raise rbac_exceptions.RbacParsingException(msg)

        return rules

    def _is_admin_context(self, roles):
        """Checks whether a role has admin context.

        If context_is_admin is contained in the policy file, then checks
        whether the given role is contained in context_is_admin. If it is not
        in the policy file, then default to context_is_admin: admin.
        """
        if 'context_is_admin' in self.rules:
            return self._allowed(
                access=self._get_access_token(roles),
                apply_rule='context_is_admin')
        return CONF.identity.admin_role in roles

    def _get_access_token(self, roles):
        roles = {r.lower() for r in roles if r}

        # Extend roles for an user with admin or member role
        if 'admin' in roles:
            roles.add('member')
        if 'member' in roles:
            roles.add('reader')

        access_token = {
            "token": {
                "roles": [{'name': r} for r in roles],
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
        # from the role, but rather from project and domain names. For more
        # information, see:
        # https://git.openstack.org/cgit/openstack/keystone/tree/keystone/token/providers/common.py?id=37ce5417418f8acbd27f3dacb70c605b0fe48301#n150
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
            message = ('Policy action "{0}" not found in policy files: '
                       '{1} or among registered policy in code defaults for '
                       '{2} service.').format(apply_rule,
                                              self.policy_files[self.service],
                                              self.service)
            LOG.debug(message)
            raise rbac_exceptions.RbacParsingException(message)
        else:
            rule = self.rules[apply_rule]
            return rule(target, access_data, o)
