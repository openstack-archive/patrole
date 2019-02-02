# Copyright 2018 AT&T Corporation.
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

from tempest.common import utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class AutoAllocationTopologyExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AutoAllocationTopologyExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('auto-allocated-topology',
                                          'network'):
            msg = "auto-allocated-topology extension not enabled."
            raise cls.skipException(msg)

    @decorators.idempotent_id('299CB831-F6B2-49CA-882B-E9A8E36945A2')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_auto_allocated_topology"],
                                 expected_error_codes=[404])
    def test_show_auto_allocated_topology(self):
        """Test show auto_allocated_topology.

        RBAC test for the neutron "get_auto_allocated_topology" policy
        """
        with self.override_role():
            self.ntp_client.get_auto_allocated_topology(
                tenant_id=self.os_primary.credentials.tenant_id)

    def _ensure_network_not_in_use(cls, network_id):
        ports = cls.ntp_client.list_ports(network_id=network_id)["ports"]

        # Every subnet within network should have a router interface
        expected_ports_count = len(
            cls.ntp_client.show_network(network_id)["network"]["subnets"])
        # Every network should have a single dhcp interface
        expected_ports_count += 1

        if len(ports) != expected_ports_count:
            msg = "Auto Allocated Topology in use."
            cls.skipException(msg)

    @decorators.idempotent_id('A0606AFE-065E-4C09-8E51-58EE7FBA30A2')
    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_auto_allocated_topology",
                                        "delete_auto_allocated_topology"],
                                 expected_error_codes=[404, 403])
    def test_delete_auto_allocated_topology(self):
        """Test delete auto_allocated_topology.

        RBAC test for the neutron "delete_auto_allocated_topology" policy
        """
        tenant_id = self.os_primary.credentials.tenant_id
        net_id = self.ntp_client.get_auto_allocated_topology(
            tenant_id=tenant_id)["auto_allocated_topology"]["id"]

        self._ensure_network_not_in_use(net_id)

        with self.override_role():
            self.ntp_client.delete_auto_allocated_topology(
                tenant_id=self.os_primary.credentials.tenant_id)
