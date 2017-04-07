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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class MultinicV210RbacTest(rbac_base.BaseV2ComputeRbacTest):

    min_microversion = '2.10'
    max_microversion = '2.36'

    @classmethod
    def setup_clients(cls):
        super(MultinicV210RbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def skip_checks(cls):
        super(MultinicV210RbacTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron is required")
        if not CONF.compute_feature_enabled.interface_attach:
            raise cls.skipException("Interface attachment is not available.")

    @classmethod
    def setup_credentials(cls):
        # This test class requires network and subnet
        cls.set_network_resources(network=True, subnet=True)
        super(MultinicV210RbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(MultinicV210RbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-multinic")
    @decorators.idempotent_id('bd3e2c74-130a-40f0-8085-124d93fe67da')
    def test_add_fixed_ip(self):
        """Add fixed IP to server."""
        interfaces = (self.interfaces_client.list_interfaces(self.server['id'])
                      ['interfaceAttachments'])
        if interfaces:
            network_id = interfaces[0]['net_id']
        else:
            network_id = self.interfaces_client.create_interface(
                self.server['id'])['interfaceAttachment']['net_id']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.add_fixed_ip(self.server['id'],
                                 networkId=network_id)
