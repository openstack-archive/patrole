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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class AgentsRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AgentsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('agent', 'network'):
            msg = "agent extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(AgentsRbacTest, cls).resource_setup()
        agents = cls.agents_client.list_agents()['agents']
        cls.agent = agents[0]

    @decorators.idempotent_id('f88e38e0-ab52-4b97-8ffa-48a27f9d199b')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_agent"],
                                 expected_error_codes=[404])
    def test_show_agent(self):
        """Show agent test.

        RBAC test for the neutron get_agent policy
        """
        with self.rbac_utils.override_role(self):
            self.agents_client.show_agent(self.agent['id'])

    @decorators.idempotent_id('8ca68fdb-eaf6-4880-af82-ba0982949dec')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_agent", "update_agent"],
                                 expected_error_codes=[404, 403])
    def test_update_agent(self):
        """Update agent test.

        RBAC test for the neutron update_agent policy
        """
        original_status = self.agent['admin_state_up']
        agent_status = {'admin_state_up': original_status}

        with self.rbac_utils.override_role(self):
            self.agents_client.update_agent(agent_id=self.agent['id'],
                                            agent=agent_status)


class L3AgentSchedulerRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(L3AgentSchedulerRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('l3_agent_scheduler', 'network'):
            msg = "l3_agent_scheduler extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(L3AgentSchedulerRbacTest, cls).resource_setup()
        cls.router = cls.create_router()
        cls.agent = None

    def setUp(self):
        super(L3AgentSchedulerRbacTest, self).setUp()
        if self.agent is not None:
            return

        # Find an agent and validate that it is correct.
        agents = self.agents_client.list_agents()['agents']
        agent = {'agent_type': None}
        for a in agents:
            if a['agent_type'] == 'L3 agent':
                agent = a
                break
        self.assertEqual(agent['agent_type'], 'L3 agent', 'Could not find '
                         'L3 agent in agent list though l3_agent_scheduler '
                         'is enabled.')
        self.agent = agent

    @decorators.idempotent_id('5d2bbdbc-40a5-43d2-828a-84dc93fcc453')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_l3-routers"])
    def test_list_routers_on_l3_agent(self):
        """List routers on L3 agent test.

        RBAC test for the neutron get_l3-routers policy
        """
        with self.rbac_utils.override_role(self):
            self.agents_client.list_routers_on_l3_agent(self.agent['id'])

    @decorators.idempotent_id('466b2a10-8747-4c09-855a-bd90a1c86ce7')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_l3-router"])
    def test_create_router_on_l3_agent(self):
        """Create router on L3 agent test.

        RBAC test for the neutron create_l3-router policy
        """
        with self.rbac_utils.override_role(self):
            self.agents_client.create_router_on_l3_agent(
                self.agent['id'], router_id=self.router['id'])
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.agents_client.delete_router_from_l3_agent,
            self.agent['id'], router_id=self.router['id'])

    @decorators.idempotent_id('8138cfc9-3e48-4a34-adf6-894077aa1be4')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["delete_l3-router"])
    def test_delete_router_from_l3_agent(self):
        """Delete router from L3 agent test.

        RBAC test for the neutron delete_l3-router policy
        """
        self.agents_client.create_router_on_l3_agent(
            self.agent['id'], router_id=self.router['id'])
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.agents_client.delete_router_from_l3_agent,
            self.agent['id'], router_id=self.router['id'])

        with self.rbac_utils.override_role(self):
            self.agents_client.delete_router_from_l3_agent(
                self.agent['id'], router_id=self.router['id'])


class DHCPAgentSchedulersRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(DHCPAgentSchedulersRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('dhcp_agent_scheduler', 'network'):
            msg = "dhcp_agent_scheduler extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(DHCPAgentSchedulersRbacTest, cls).resource_setup()
        cls.agent = None

    def setUp(self):
        super(DHCPAgentSchedulersRbacTest, self).setUp()
        if self.agent is not None:
            return

        # Find a DHCP agent and validate that it is correct.
        agents = self.agents_client.list_agents()['agents']
        agent = {'agent_type': None}
        for a in agents:
            if a['agent_type'] == 'DHCP agent':
                agent = a
                break
        self.assertEqual(agent['agent_type'], 'DHCP agent', 'Could not find '
                         'DHCP agent in agent list though dhcp_agent_scheduler'
                         ' is enabled.')
        self.agent = agent

    def _create_and_prepare_network_for_agent(self, agent_id):
        """Create network and ensure it is not hosted by agent_id."""
        network_id = self.create_network()['id']

        if self._check_network_in_dhcp_agent(network_id, agent_id):
            self.agents_client.delete_network_from_dhcp_agent(
                agent_id=agent_id, network_id=network_id)

        return network_id

    def _check_network_in_dhcp_agent(self, network_id, agent_id):
        networks = self.agents_client.list_networks_hosted_by_one_dhcp_agent(
            agent_id)['networks'] or []
        return network_id in [network['id'] for network in networks]

    @decorators.idempotent_id('dc84087b-4c2a-4878-8ed0-40370e19da17')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_dhcp-networks"])
    def test_list_networks_hosted_by_one_dhcp_agent(self):
        """List networks hosted by one DHCP agent test.

        RBAC test for the neutron get_dhcp-networks policy
        """
        with self.rbac_utils.override_role(self):
            self.agents_client.list_networks_hosted_by_one_dhcp_agent(
                self.agent['id'])

    @decorators.idempotent_id('14e014ac-f355-46d3-b6d8-98f2c9ec1610')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_dhcp-network"])
    def test_add_dhcp_agent_to_network(self):
        """Add DHCP agent to network test.

        RBAC test for the neutron create_dhcp-network policy
        """
        network_id = self._create_and_prepare_network_for_agent(
            self.agent['id'])

        with self.rbac_utils.override_role(self):
            self.agents_client.add_dhcp_agent_to_network(
                self.agent['id'], network_id=network_id)
        # Clean up is not necessary and might result in 409 being raised.

    @decorators.idempotent_id('937a4302-4b49-407d-9980-5843d7badc38')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["delete_dhcp-network"])
    def test_delete_network_from_dhcp_agent(self):
        """Delete DHCP agent from network test.

        RBAC test for the neutron delete_dhcp-network policy
        """
        network_id = self._create_and_prepare_network_for_agent(
            self.agent['id'])
        self.agents_client.add_dhcp_agent_to_network(
            self.agent['id'], network_id=network_id)
        # Clean up is not necessary and might result in 409 being raised.

        with self.rbac_utils.override_role(self):
            self.agents_client.delete_network_from_dhcp_agent(
                self.agent['id'], network_id=network_id)


class L3AgentsExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(L3AgentsExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('l3_agent_scheduler', 'network'):
            msg = "l3_agent_scheduler extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(L3AgentsExtRbacTest, cls).resource_setup()
        name = data_utils.rand_name(cls.__name__ + '-Router')
        cls.router = cls.ntp_client.create_router(name)['router']

    @decorators.idempotent_id('5d2bbdbc-40a5-43d2-828a-84dc93bcd321')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_l3-agents"])
    def test_list_l3_agents_on_router(self):
        """List L3 agents on router test.

        RBAC test for the neutron get_l3-agents policy
        """
        with self.rbac_utils.override_role(self):
            # NOTE: It is not empty list since it's a special case where
            # policy.enforce is called from the controller.
            self.ntp_client.list_l3_agents_hosting_router(self.router['id'])
