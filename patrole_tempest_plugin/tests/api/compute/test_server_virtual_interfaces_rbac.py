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

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base as base

CONF = config.CONF


class ServerVirtualInterfacesRbacTest(base.BaseV2ComputeRbacTest):

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-virtual-interfaces")
    @decorators.idempotent_id('fc719ae3-0f73-4689-8378-1b841f0f2818')
    def test_list_virtual_interfaces(self):
        server = self.create_test_server(wait_until='ACTIVE')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        if CONF.service_available.neutron:
            msg = "Listing virtual interfaces is not supported by this cloud."
            with self.assertRaisesRegex(exceptions.BadRequest, msg):
                self.servers_client.list_virtual_interfaces(server['id'])
        else:
            self.servers_client.list_virtual_interfaces(server['id'])
