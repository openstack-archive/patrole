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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base as base


class ComputeLockServersRbacTest(base.BaseV2ComputeRbacTest):

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:lock")
    @decorators.idempotent_id('b81e10fb-1864-498f-8c1d-5175c6fec5fb')
    def test_lock_server(self):
        server = self.create_test_server(wait_until='ACTIVE')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.lock_server(server['id'])
        self.addCleanup(self.servers_client.unlock_server, server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:unlock")
    @decorators.idempotent_id('d50ef8e8-4bce-11e7-b114-b2f933d5fe66')
    def test_unlock_server(self):
        server = self.create_test_server(wait_until='ACTIVE')
        self.servers_client.lock_server(server['id'])
        self.addCleanup(self.servers_client.unlock_server, server['id'])
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.unlock_server(server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:unlock:unlock_override")
    @decorators.idempotent_id('40dfeef9-73ee-48a9-be19-a219875de457')
    def test_unlock_server_override(self):
        server = self.create_test_server(wait_until='ACTIVE')
        # In order to trigger the unlock:unlock_override policy instead
        # of the unlock policy, the server must be locked by a different
        # user than the one who is attempting to unlock it.
        self.os_admin.servers_client.lock_server(server['id'])
        self.addCleanup(self.servers_client.unlock_server, server['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.unlock_server(server['id'])
