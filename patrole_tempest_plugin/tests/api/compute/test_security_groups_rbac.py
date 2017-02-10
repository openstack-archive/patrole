#    Copyright 2017 AT&T Corporation.
#    All Rights Reserved.
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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.compute import rbac_base


class SecurityGroupsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(SecurityGroupsRbacTest, self).tearDown()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-security-groups")
    @decorators.idempotent_id('4ac58e49-48c1-4fca-a6c3-3f95fb99eb77')
    def test_server_security_groups(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.security_groups_client.list_security_groups()
