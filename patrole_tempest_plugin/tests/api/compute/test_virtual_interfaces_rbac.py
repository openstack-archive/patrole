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

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


# TODO(rb560u): Remove this test class once the nova queens branch goes into
# extended maintenance mode.
class VirtualInterfacesRbacTest(rbac_base.BaseV2ComputeRbacTest):
    # The compute os-virtual-interfaces API is deprecated from the Microversion
    # 2.44 onward. For more information, see:
    # https://developer.openstack.org/api-ref/compute/#servers-virtual-interfaces-servers-os-virtual-interfaces-deprecated
    depends_on_nova_network = True
    max_microversion = '2.43'

    @classmethod
    def setup_credentials(cls):
        # This test needs a network and a subnet
        cls.set_network_resources(network=True, subnet=True)
        super(VirtualInterfacesRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(VirtualInterfacesRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-virtual-interfaces")
    @decorators.idempotent_id('fc719ae3-0f73-4689-8378-1b841f0f2818')
    def test_list_virtual_interfaces(self):
        """Test list virtual interfaces, part of os-virtual-interfaces.

        If Neutron is available, then call the API and expect it to fail
        with a 400 BadRequest (policy enforcement is done before that happens).
        """
        with self.rbac_utils.override_role(self):
            if CONF.service_available.neutron:
                msg = ("Listing virtual interfaces is not supported by this "
                       "cloud.")
                with self.assertRaisesRegex(lib_exc.BadRequest, msg):
                    self.servers_client.list_virtual_interfaces(
                        self.server['id'])
            else:
                self.servers_client.list_virtual_interfaces(self.server['id'])
