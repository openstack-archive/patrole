# Copyright 2016 AT&T Corp
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

import os

from oslo_config import cfg
from oslo_log import log as logging
from oslo_policy import _checks
from oslo_policy import policy
from tempest import config

from patrole_tempest_plugin.rbac_exceptions import RbacResourceSetupFailed

CONF = config.CONF
LOG = logging.getLogger(__name__)

RULES_TO_SKIP = []
TESTED_RULES = []
PARSED_RULES = []


class RbacPolicyConverter(object):
    """A class for parsing policy rules into lists of allowed roles.

    RBAC testing requires that each rule in a policy file be broken up into
    the roles that constitute it. This class automates that process.
    """

    def __init__(self, service, path=None):
        """Initialization of Policy Converter

        Parse policy files to create dictionary mapping
        policy actions to roles.
        :param service: type string
        :param path: type string
        """

        if path is None:
            path = '/etc/{0}/policy.json'.format(service)

        if not os.path.isfile(path):
            raise RbacResourceSetupFailed('Policy file for service: {0}, {1}'
                                          ' not found.'.format(service, path))

        self.default_roles = CONF.rbac.rbac_roles
        self.rules = {}

        self._get_roles_for_each_rule_in_policy_file(path)

    def _get_roles_for_each_rule_in_policy_file(self, path):
        """Gets the roles for each rule in the policy file at given path."""

        global PARSED_RULES
        global TESTED_RULES
        global RULES_TO_SKIP

        rule_to_roles_dict = {}
        enforcer = self._init_policy_enforcer(path)

        base_rules = set()
        for rule_name, rule_checker in enforcer.rules.items():
            if isinstance(rule_checker, _checks.OrCheck):
                for sub_rule in rule_checker.rules:
                    if hasattr(sub_rule, 'match'):
                        base_rules.add(sub_rule.match)
            elif isinstance(rule_checker, _checks.RuleCheck):
                if hasattr(rule_checker, 'match'):
                    base_rules.add(rule_checker.match)

        RULES_TO_SKIP.extend(base_rules)
        generic_check_dict = self._get_generic_check_dict(enforcer.rules)

        for rule_name, rule_checker in enforcer.rules.items():
            PARSED_RULES.append(rule_name)

            if rule_name in RULES_TO_SKIP:
                continue
            if isinstance(rule_checker, _checks.GenericCheck):
                continue

            # Determine whether each role is contained within the current rule.
            for role in self.default_roles:
                roles = {'roles': [role]}
                roles.update(generic_check_dict)
                is_role_in_rule = rule_checker(
                    generic_check_dict, roles, enforcer)
                if is_role_in_rule:
                    rule_to_roles_dict.setdefault(rule_name, set())
                    rule_to_roles_dict[rule_name].add(role)

        self.rules = rule_to_roles_dict

    def _init_policy_enforcer(self, policy_file):
        """Initializes oslo policy enforcer"""

        def find_file(path):
            realpath = os.path.realpath(path)
            if os.path.isfile(realpath):
                return realpath
            else:
                return None

        CONF = cfg.CONF
        CONF.find_file = find_file

        enforcer = policy.Enforcer(CONF,
                                   policy_file=policy_file,
                                   rules=None,
                                   default_rule=None,
                                   use_conf=True)
        enforcer.load_rules()
        return enforcer

    def _get_generic_check_dict(self, enforcer_rules):
        """Creates permissions dictionary that oslo policy uses

        to determine if a user can perform an action.
        """

        generic_checks = set()
        for rule_checker in enforcer_rules.values():
            entries = set()
            self._get_generic_check_entries(rule_checker, entries)
            generic_checks |= entries
        return {e: '' for e in generic_checks}

    def _get_generic_check_entries(self, rule_checker, entries):
        if isinstance(rule_checker, _checks.GenericCheck):
            if hasattr(rule_checker, 'match'):
                if rule_checker.match.startswith('%(') and\
                    rule_checker.match.endswith(')s'):
                    entries.add(rule_checker.match[2:-2])
        if hasattr(rule_checker, 'rule'):
            if isinstance(rule_checker.rule, _checks.GenericCheck) and\
                hasattr(rule_checker.rule, 'match'):
                if rule_checker.rule.match.startswith('%(') and\
                    rule_checker.rule.match.endswith(')s'):
                    entries.add(rule_checker.rule.match[2:-2])
        if hasattr(rule_checker, 'rules'):
            for rule in rule_checker.rules:
                self._get_generic_check_entries(rule, entries)
