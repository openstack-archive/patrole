# Copyright 2016 AT&T Corp
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.network import rbac_base as base

CONF = config.CONF


class RbacNetworksTest(base.BaseNetworkRbacTest):

    @classmethod
    def setup_clients(cls):
        super(RbacNetworksTest, cls).setup_clients()
        cls.networks_client = cls.os.networks_client
        cls.subnet_client = cls.os.subnets_client

    @classmethod
    def resource_setup(cls):
        super(RbacNetworksTest, cls).resource_setup()

        network_name = data_utils.rand_name('rbac-admin-network-')

        post_body = {'name': network_name}
        body = cls.networks_client.create_network(**post_body)
        cls.admin_network = body['network']
        cls.networks.append(cls.admin_network)

        # Create a subnet by admin user
        cls.cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)

        cls.admin_subnet = cls.create_subnet(cls.admin_network,
                                             cidr=cls.cidr,
                                             mask_bits=24,
                                             enable_dhcp=False)

    def _delete_network(self, network):
        # Deleting network also deletes its subnets if exists
        self.networks_client.delete_network(network['id'])
        if network in self.networks:
            self.networks.remove(network)
        for subnet in self.subnets:
            if subnet['network_id'] == network['id']:
                self.subnets.remove(subnet)

    def _create_network(self,
                        shared=None,
                        router_external=None,
                        router_private=None,
                        provider_network_type=None,
                        provider_physical_network=None,
                        provider_segmentation_id=None):

        network_name = data_utils.rand_name('test-network-')
        post_body = {'name': network_name}

        if shared is not None:
            post_body['shared'] = shared
        if router_external is not None:
            post_body['router:external'] = router_external
        if router_private is not None:
            post_body['router:private'] = router_private
        if provider_network_type is not None:
            post_body['provider:network_type'] = provider_network_type
        if provider_physical_network is not None:
            post_body['provider:physical_network'] = provider_physical_network
        if provider_segmentation_id is not None:
            post_body['provider:segmentation_id'] = provider_segmentation_id

        body = self.networks_client.create_network(**post_body)
        network = body['network']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_network, network)
        self.assertEqual('ACTIVE', network['status'])
        return network

    def _update_network(self,
                        admin=None,
                        shared_network=None,
                        router_external=None,
                        router_private=None,
                        segments=None):

        # update a network that has been created during class setup
        net_id = self.admin_network['id']

        post_body = {}
        updated_network = None

        if admin is not None:
            post_body['admin_state_up'] = admin
        elif shared_network is not None:
            post_body['shared'] = shared_network
        elif router_external is not None:
            post_body['router:external'] = router_external
        elif router_private is not None:
            post_body['router:private'] = router_private
        elif segments is not None:
            post_body['segments'] = segments
        else:
            return updated_network

        body = self.networks_client.update_network(net_id, **post_body)
        updated_network = body['network']
        return updated_network

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(RbacNetworksTest, self).tearDown()

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_network")
    @decorators.idempotent_id('95b9baab-1ece-4e2b-89c8-8d671d974e54')
    def test_create_network(self):

        """Create Network Test

        RBAC test for the neutron create_network policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_network()

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_network:shared")
    @decorators.idempotent_id('ccabf2a9-28c8-44b2-80e6-ffd65d43eef2')
    def test_create_network_shared(self):

        """Create Shared Network Test

        RBAC test for the neutron create_network:shared policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_network(shared=True)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_network:router:external")
    @decorators.idempotent_id('51adf2a7-739c-41e0-8857-3b4c460cbd24')
    def test_create_network_router_external(self):

        """Create External Router Network Test

        RBAC test for the neutron create_network:router:external policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_network(router_external=True)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_network:provider:network_type")
    @decorators.idempotent_id('3c42f7b8-b80c-44ef-8fa4-69ec4b1836bc')
    def test_create_network_provider_network_type(self):

        """Create Provider Network Test

        RBAC test for the neutron create_network:provider:network_type policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_network(provider_network_type='vxlan')

    @rbac_rule_validation.action(
        service="neutron",
        rule="create_network:provider:physical_network")
    @decorators.idempotent_id('f458033b-2d52-4fd1-86db-e31e111d6fac')
    def test_create_network_provider_physical_network(self):

        """Create Provider Physical Network Test

        RBAC test for the neutron create_network:provider:physical_network
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_network(provider_network_type='flat',
                             provider_physical_network='ph-eth0')

    @rbac_rule_validation.action(
        service="neutron",
        rule="create_network:provider:segmentation_id")
    @decorators.idempotent_id('b9decb7b-68ef-4504-b99b-41edbf7d2af5')
    def test_create_network_provider_segmentation_id(self):

        """Create Provider Network Segmentation Id Test

        RBAC test for the neutron create_network:provider:segmentation_id
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_network(provider_network_type='vxlan',
                             provider_segmentation_id=200)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_network")
    @decorators.idempotent_id('6485bb4e-e110-48ae-83e1-3ec8b40c3107')
    def test_update_network(self):

        """Update Network Test

        RBAC test for the neutron update_network policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        updated_network = self._update_network(admin=False)
        self.assertEqual(updated_network['admin_state_up'], False)

        # Revert back to True
        updated_network = self._update_network(admin=True)
        self.assertEqual(updated_network['admin_state_up'], True)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_network:shared")
    @decorators.idempotent_id('37ea3e33-47d9-49fc-9bba-1af98fbd46d6')
    def test_update_network_shared(self):

        """Update Shared Network Test

        RBAC test for the neutron update_network:shared policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        updated_network = self._update_network(shared_network=True)
        self.assertEqual(updated_network['shared'], True)

        # Revert back to False
        updated_network = self._update_network(shared_network=False)
        self.assertEqual(updated_network['shared'], False)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_network:router:external")
    @decorators.idempotent_id('34884c22-499b-4960-97f1-e2ed8522a9c9')
    def test_update_network_router_external(self):

        """Update Network Router External Test

        RBAC test for the neutron update_network:router:external policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        updated_network = self._update_network(router_external=True)
        self.assertEqual(updated_network['router:external'], True)

        # Revert back to False
        updated_network = self._update_network(router_external=False)
        self.assertEqual(updated_network['router:external'], False)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_network")
    @decorators.idempotent_id('0eb62d04-338a-4ff4-a8fa-534e52110534')
    def test_show_network(self):

        """Show Network Test

        RBAC test for the neutron get_network policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        # show a network that has been created during class setup
        self.networks_client.show_network(self.admin_network['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_network:router:external")
    @decorators.idempotent_id('529e4814-22e9-413f-af48-8fefcd637344')
    def test_show_network_router_external(self):

        """Show Network Router External Test

        RBAC test for the neutron get_network:router:external policy
        """
        post_body = {'fields': 'router:external'}

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.networks_client.show_network(self.admin_network['id'],
                                          **post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_network:provider:network_type")
    @decorators.idempotent_id('6521dd60-0950-458b-8491-09d3c84ac0f4')
    def test_show_network_provider_network_type(self):

        """Show Network Prodiver Network Type Test

        RBAC test for the neutron get_network:provider:network_type policy
        """
        post_body = {'fields': 'provider:network_type'}

        rbac_utils.switch_role(self, switchToRbacRole=True)
        body = self.networks_client.show_network(self.admin_network['id'],
                                                 **post_body)
        showed_net = body['network']

        if len(showed_net) == 0:
            raise rbac_exceptions.RbacActionFailed

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_network:provider:physical_network")
    @decorators.idempotent_id('c049f11a-240c-4a85-ad43-a4d3fd0a5e39')
    def test_show_network_provider_physical_network(self):

        """Show Network Provider Physical Network Test

        RBAC test for the neutron get_network:provider:physical_network policy
        """
        post_body = {'fields': 'provider:physical_network'}

        rbac_utils.switch_role(self, switchToRbacRole=True)
        body = self.networks_client.show_network(self.admin_network['id'],
                                                 **post_body)
        showed_net = body['network']

        if len(showed_net) == 0:
            raise rbac_exceptions.RbacActionFailed

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_network:provider:segmentation_id")
    @decorators.idempotent_id('38d9f085-6365-4f81-bac9-c53c294d727e')
    def test_show_network_provider_segmentation_id(self):

        """Show Network Provider Segmentation Id Test

        RBAC test for the neutron get_network:provider:segmentation_id policy
        """
        post_body = {'fields': 'provider:segmentation_id'}

        rbac_utils.switch_role(self, switchToRbacRole=True)
        body = self.networks_client.show_network(self.admin_network['id'],
                                                 **post_body)
        showed_net = body['network']

        if len(showed_net) == 0:
            raise rbac_exceptions.RbacActionFailed

        key = showed_net.get('provider:segmentation_id', "NotFound")
        self.assertIsNot(key, "NotFound")

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_network")
    @decorators.idempotent_id('56ca50ed-ac58-49d6-b239-ed39e7124d5c')
    def test_delete_network(self):

        """Delete Network Test

        RBAC test for the neutron delete_network policy
        """
        network = self._create_network()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.networks_client.delete_network(network['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_subnet")
    @decorators.idempotent_id('44f42aaf-8a9a-4678-868a-b8fe82689554')
    def test_create_subnet(self):

        """Create Subnet Test

        RBAC test for the neutron create_subnet policy
        """
        network = self._create_network()
        self.assertEqual('ACTIVE', network['status'])

        rbac_utils.switch_role(self, switchToRbacRole=True)
        # Create a subnet
        self.create_subnet(network, enable_dhcp=False)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_subnet")
    @decorators.idempotent_id('eb88be84-2465-482b-a40b-5201acb41152')
    def test_show_subnet(self):

        """Show Subnet Test

        RBAC test for the neutron get_subnet policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.subnets_client.show_subnet(self.admin_subnet['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_subnet")
    @decorators.idempotent_id('1bfeaec5-83b9-4140-8138-93a0a9d04cee')
    def test_update_subnet(self):

        """Update Subnet Test

        RBAC test for the neutron update_subnet policy
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.subnets_client.update_subnet(self.admin_subnet['id'],
                                          name="New_subnet")

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_subnet")
    @decorators.idempotent_id('1ad1400f-dc84-4edb-9674-b33bbfb0d3e3')
    def test_delete_subnet(self):

        """Delete Subnet Test

        RBAC test for the neutron delete_subnet policy
        """
        # Create a network using admin privilege
        network = self._create_network()
        self.assertEqual('ACTIVE', network['status'])

        # Create a subnet using admin privilege
        subnet = self.create_subnet(network, enable_dhcp=False)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        # Delete the subnet
        self.subnets_client.delete_subnet(subnet['id'])
