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

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base as base

CONF = config.CONF


class ServerVirtualInterfacesRbacTest(base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ServerVirtualInterfacesRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-virtual-interfaces")
    @decorators.idempotent_id('fc719ae3-0f73-4689-8378-1b841f0f2818')
    def test_list_virtual_interfaces(self):
        server = self.create_test_server(wait_until='ACTIVE')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.client.list_virtual_interfaces(server['id'])
        except exceptions.ServerFault as e:
            raise rbac_exceptions.RbacActionFailed(e)
        except exceptions.BadRequest as e:
            msg = "Listing virtual interfaces is not supported by this cloud."
            if msg == str(e.resp_body['message']):
                raise self.skipException(msg)
            else:
                raise e
