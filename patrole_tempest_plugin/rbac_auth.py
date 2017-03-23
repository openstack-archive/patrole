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

import testtools

from oslo_log import log as logging

from tempest import config

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_policy_parser

LOG = logging.getLogger(__name__)
CONF = config.CONF


class RbacAuthority(object):
    def __init__(self, tenant_id, user_id, service=None):
        self.policy_parser = rbac_policy_parser.RbacPolicyParser(
            tenant_id, user_id, service)

    def get_permission(self, rule_name, role):
        try:
            is_allowed = self.policy_parser.allowed(rule_name, role)
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
