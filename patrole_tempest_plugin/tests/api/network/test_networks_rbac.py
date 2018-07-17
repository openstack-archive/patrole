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

import netaddr

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base

CONF = config.CONF


class NetworksRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def resource_setup(cls):
        super(NetworksRbacTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
        cls.subnet = cls.create_subnet(
            cls.network, cidr=cls.cidr, mask_bits=24, enable_dhcp=False)

    def _create_network(self,
                        router_external=None,
                        router_private=None,
                        provider_network_type=None,
                        provider_physical_network=None,
                        provider_segmentation_id=None,
                        **kwargs):
        if router_external is not None:
            kwargs['router:external'] = router_external
        if router_private is not None:
            kwargs['router:private'] = router_private
        if provider_network_type is not None:
            kwargs['provider:network_type'] = provider_network_type
        if provider_physical_network is not None:
            kwargs['provider:physical_network'] = provider_physical_network
        if provider_segmentation_id is not None:
            kwargs['provider:segmentation_id'] = provider_segmentation_id

        network_name = data_utils.rand_name(
            self.__class__.__name__ + '-Network')
        network = self.create_network(network_name=network_name, **kwargs)
        return network

    def _update_network(self,
                        net_id=None,
                        admin=None,
                        shared_network=None,
                        router_external=None,
                        router_private=None,
                        segments=None,
                        **kwargs):
        if not net_id:
            net_id = self.network['id']

        if admin is not None:
            kwargs['admin_state_up'] = admin
        elif shared_network is not None:
            kwargs['shared'] = shared_network
        elif router_external is not None:
            kwargs['router:external'] = router_external
        elif router_private is not None:
            kwargs['router:private'] = router_private
        elif segments is not None:
            kwargs['segments'] = segments

        updated_network = self.networks_client.update_network(
            net_id, **kwargs)['network']
        return updated_network

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_network")
    @decorators.idempotent_id('95b9baab-1ece-4e2b-89c8-8d671d974e54')
    def test_create_network(self):

        """Create Network Test

        RBAC test for the neutron create_network policy
        """
        with self.rbac_utils.override_role(self):
            self._create_network()

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_network",
                                        "create_network:is_default"],
                                 expected_error_codes=[403, 403])
    @decorators.idempotent_id('28602661-5ac7-407e-b739-e393f619f5e3')
    def test_create_network_is_default(self):

        """Create Is Default Network Test

        RBAC test for the neutron create_network:is_default policy
        """
        try:
            with self.rbac_utils.override_role(self):
                self._create_network(is_default=True)
        except lib_exc.Conflict as exc:
            # A default network might already exist
            self.assertIn('A default external network already exists',
                          str(exc))

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_network",
                                        "create_network:shared"],
                                 expected_error_codes=[403, 403])
    @decorators.idempotent_id('ccabf2a9-28c8-44b2-80e6-ffd65d43eef2')
    def test_create_network_shared(self):

        """Create Shared Network Test

        RBAC test for the neutron create_network:shared policy
        """
        with self.rbac_utils.override_role(self):
            self._create_network(shared=True)

    @utils.requires_ext(extension='external-net', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_network",
                                        "create_network:router:external"],
                                 expected_error_codes=[403, 403])
    @decorators.idempotent_id('51adf2a7-739c-41e0-8857-3b4c460cbd24')
    def test_create_network_router_external(self):

        """Create External Router Network Test

        RBAC test for the neutron create_network:router:external policy
        """
        with self.rbac_utils.override_role(self):
            self._create_network(router_external=True)

    @utils.requires_ext(extension='provider', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["create_network",
               "create_network:provider:physical_network"],
        expected_error_codes=[403, 403])
    @decorators.idempotent_id('76783fed-9ff3-4499-a0d1-82d99eec364e')
    def test_create_network_provider_physical_network(self):

        """Create Network Physical Network Provider Test

        RBAC test for neutron create_network:provider:physical_network policy
        """
        try:
            with self.rbac_utils.override_role(self):
                self._create_network(provider_physical_network='provider',
                                     provider_network_type='flat')
        except lib_exc.BadRequest as exc:
            # There probably won't be a physical network called 'provider', but
            # we aren't testing state of the network
            self.assertIn("Invalid input for operation: physical_network " +
                          "'provider' unknown for flat provider network.",
                          str(exc))

    @utils.requires_ext(extension='provider', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["create_network",
               "create_network:provider:network_type"],
        expected_error_codes=[403, 403])
    @decorators.idempotent_id('3c42f7b8-b80c-44ef-8fa4-69ec4b1836bc')
    def test_create_network_provider_network_type(self):

        """Create Provider Network Test

        RBAC test for the neutron create_network:provider:network_type policy
        """
        with self.rbac_utils.override_role(self):
            self._create_network(provider_network_type='vxlan')

    @utils.requires_ext(extension='provider', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["create_network",
               "create_network:provider:segmentation_id"],
        expected_error_codes=[403, 403])
    @decorators.idempotent_id('b9decb7b-68ef-4504-b99b-41edbf7d2af5')
    def test_create_network_provider_segmentation_id(self):

        """Create Provider Network Segmentation Id Test

        RBAC test for the neutron create_network:provider:segmentation_id
        """
        with self.rbac_utils.override_role(self):
            self._create_network(provider_network_type='vxlan',
                                 provider_segmentation_id=200)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network", "update_network"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('6485bb4e-e110-48ae-83e1-3ec8b40c3107')
    def test_update_network(self):

        """Update Network Test

        RBAC test for the neutron update_network policy
        """
        updated_name = data_utils.rand_name(
            self.__class__.__name__ + '-Network')

        with self.rbac_utils.override_role(self):
            self._update_network(name=updated_name)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network",
                                        "update_network",
                                        "update_network:shared"],
                                 expected_error_codes=[404, 403, 403])
    @decorators.idempotent_id('37ea3e33-47d9-49fc-9bba-1af98fbd46d6')
    def test_update_network_shared(self):

        """Update Shared Network Test

        RBAC test for the neutron update_network:shared policy
        """
        with self.rbac_utils.override_role(self):
            self._update_network(shared_network=True)
        self.addCleanup(self._update_network, shared_network=False)

    @utils.requires_ext(extension='external-net', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network",
                                        "update_network",
                                        "update_network:router:external"],
                                 expected_error_codes=[404, 403, 403])
    @decorators.idempotent_id('34884c22-499b-4960-97f1-e2ed8522a9c9')
    def test_update_network_router_external(self):

        """Update Network Router External Test

        RBAC test for the neutron update_network:router:external policy
        """
        network = self._create_network()
        with self.rbac_utils.override_role(self):
            self._update_network(net_id=network['id'], router_external=True)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_network",
                                 expected_error_code=404)
    @decorators.idempotent_id('0eb62d04-338a-4ff4-a8fa-534e52110534')
    def test_show_network(self):

        """Show Network Test

        RBAC test for the neutron get_network policy
        """
        with self.rbac_utils.override_role(self):
            self.networks_client.show_network(self.network['id'])

    @utils.requires_ext(extension='external-net', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network",
                                        "get_network:router:external"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('529e4814-22e9-413f-af48-8fefcd637344')
    def test_show_network_router_external(self):

        """Show Network Router External Test

        RBAC test for the neutron get_network:router:external policy
        """
        kwargs = {'fields': 'router:external'}

        with self.rbac_utils.override_role(self):
            retrieved_network = self.networks_client.show_network(
                self.network['id'], **kwargs)['network']

        if len(retrieved_network) == 0:
            raise rbac_exceptions.RbacMalformedResponse(empty=True)

    @utils.requires_ext(extension='provider', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network",
                                        "get_network:provider:network_type"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('6521dd60-0950-458b-8491-09d3c84ac0f4')
    def test_show_network_provider_network_type(self):

        """Show Network Prodiver Network Type Test

        RBAC test for the neutron get_network:provider:network_type policy
        """
        kwargs = {'fields': 'provider:network_type'}

        with self.rbac_utils.override_role(self):
            retrieved_network = self.networks_client.show_network(
                self.network['id'], **kwargs)['network']

        if len(retrieved_network) == 0:
            raise rbac_exceptions.RbacMalformedResponse(empty=True)

    @utils.requires_ext(extension='provider', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["get_network",
               "get_network:provider:physical_network"],
        expected_error_codes=[404, 403])
    @decorators.idempotent_id('c049f11a-240c-4a85-ad43-a4d3fd0a5e39')
    def test_show_network_provider_physical_network(self):

        """Show Network Provider Physical Network Test

        RBAC test for the neutron get_network:provider:physical_network policy
        """
        kwargs = {'fields': 'provider:physical_network'}

        with self.rbac_utils.override_role(self):
            retrieved_network = self.networks_client.show_network(
                self.network['id'], **kwargs)['network']

        if len(retrieved_network) == 0:
            raise rbac_exceptions.RbacMalformedResponse(empty=True)

    @utils.requires_ext(extension='provider', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["get_network",
               "get_network:provider:segmentation_id"],
        expected_error_codes=[404, 403])
    @decorators.idempotent_id('38d9f085-6365-4f81-bac9-c53c294d727e')
    def test_show_network_provider_segmentation_id(self):

        """Show Network Provider Segmentation Id Test

        RBAC test for the neutron get_network:provider:segmentation_id policy
        """
        kwargs = {'fields': 'provider:segmentation_id'}

        with self.rbac_utils.override_role(self):
            retrieved_network = self.networks_client.show_network(
                self.network['id'], **kwargs)['network']

        if len(retrieved_network) == 0:
            raise rbac_exceptions.RbacMalformedResponse(empty=True)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network", "delete_network"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('56ca50ed-ac58-49d6-b239-ed39e7124d5c')
    def test_delete_network(self):

        """Delete Network Test

        RBAC test for the neutron delete_network policy
        """
        network = self._create_network()
        with self.rbac_utils.override_role(self):
            self.networks_client.delete_network(network['id'])

    @utils.requires_ext(extension='dhcp_agent_scheduler', service='network')
    @decorators.idempotent_id('b524f19f-fbb4-4d11-a85d-03bfae17bf0e')
    @rbac_rule_validation.action(service="neutron",
                                 rule="get_dhcp-agents")
    def test_list_dhcp_agents_on_hosting_network(self):

        """List DHCP Agents on Hosting Network Test

        RBAC test for the neutron "get_dhcp-agents" policy
        """
        with self.rbac_utils.override_role(self):
            self.networks_client.list_dhcp_agents_on_hosting_network(
                self.network['id'])
