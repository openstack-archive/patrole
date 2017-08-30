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

from tempest.common.utils import net_utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class RouterRbacTest(base.BaseNetworkRbacTest):
    @classmethod
    def skip_checks(cls):
        super(RouterRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(RouterRbacTest, cls).resource_setup()
        # Create a network with external gateway so that
        # ``external_gateway_info`` policies can be validated.
        post_body = {'router:external': True}
        cls.network = cls.create_network(**post_body)
        cls.subnet = cls.create_subnet(cls.network)
        cls.ip_range = netaddr.IPRange(
            cls.subnet['allocation_pools'][0]['start'],
            cls.subnet['allocation_pools'][0]['end'])
        cls.router = cls.create_router()

    def _get_unused_ip_address(self):
        unused_ip = net_utils.get_unused_ip_addresses(self.ports_client,
                                                      self.subnets_client,
                                                      self.network['id'],
                                                      self.subnet['id'],
                                                      1)
        return unused_ip[0]

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_router")
    @decorators.idempotent_id('acc5005c-bdb6-4192-bc9f-ece9035bb488')
    def test_create_router(self):
        """Create Router

        RBAC test for the neutron create_router policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        router = self.routers_client.create_router()
        self.addCleanup(self.routers_client.delete_router,
                        router['router']['id'])

    @decorators.idempotent_id('6139eb97-95c0-40d8-a109-99de11ab2e5e')
    @test.requires_ext(extension='l3-ha', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rule="create_router:ha")
    def test_create_high_availability_router(self):
        """Create high-availability router

        RBAC test for the neutron create_router:ha policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        router = self.routers_client.create_router(ha=True)
        self.addCleanup(self.routers_client.delete_router,
                        router['router']['id'])

    @decorators.idempotent_id('c6254ca6-2728-412d-803d-d4aa3935e56d')
    @test.requires_ext(extension='dvr', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rule="create_router:distributed")
    def test_create_distributed_router(self):
        """Create distributed router

        RBAC test for the neutron create_router:distributed policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        router = self.routers_client.create_router(distributed=True)
        self.addCleanup(self.routers_client.delete_router,
                        router['router']['id'])

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rule="create_router:external_gateway_info:enable_snat")
    @decorators.idempotent_id('3c5acd49-0ec7-4109-ab51-640557b48ebc')
    def test_create_router_enable_snat(self):
        """Create Router Snat

        RBAC test for the neutron
        create_router:external_gateway_info:enable_snat policy
        """
        name = data_utils.rand_name(self.__class__.__name__ + '-snat-router')
        external_gateway_info = {'network_id': self.network['id'],
                                 'enable_snat': True}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        router = self.routers_client.create_router(
            name=name, external_gateway_info=external_gateway_info)
        self.addCleanup(self.routers_client.delete_router,
                        router['router']['id'])

    @rbac_rule_validation.action(
        service="neutron",
        rule="create_router:external_gateway_info:external_fixed_ips")
    @decorators.idempotent_id('d0354369-a040-4349-b869-645c8aed13cd')
    def test_create_router_external_fixed_ips(self):
        """Create Router Fixed IPs

        RBAC test for the neutron
        create_router:external_gateway_info:external_fixed_ips policy
        """
        name = data_utils.rand_name(self.__class__.__name__ + '-snat-router')

        unused_ip = self._get_unused_ip_address()
        external_fixed_ips = {'subnet_id': self.subnet['id'],
                              'ip_address': unused_ip}
        external_gateway_info = {'network_id': self.network['id'],
                                 'enable_snat': False,  # Default is True.
                                 'external_fixed_ips': [external_fixed_ips]}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        router = self.routers_client.create_router(
            name=name, external_gateway_info=external_gateway_info)
        self.addCleanup(self.routers_client.delete_router,
                        router['router']['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_router",
                                 expected_error_code=404)
    @decorators.idempotent_id('bfbdbcff-f115-4d3e-8cd5-6ada33fd0e21')
    def test_show_router(self):
        """Get Router

        RBAC test for the neutron get_router policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Prevent other policies from being enforced by using barebones fields.
        self.routers_client.show_router(self.router['id'], fields=['id'])

    @decorators.idempotent_id('3ed26ea2-b419-410c-b4b5-576c1edafa06')
    @test.requires_ext(extension='dvr', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rule="get_router:distributed")
    def test_show_distributed_router(self):
        """Get distributed router

        RBAC test for the neutron get_router:distributed policy
        """
        router = self.routers_client.create_router(distributed=True)['router']
        self.addCleanup(self.routers_client.delete_router, router['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        retrieved_fields = self.routers_client.show_router(
            router['id'], fields=['distributed'])['router']

        # Rather than throwing a 403, the field is not present, so raise exc.
        if 'distributed' not in retrieved_fields:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute='distributed')

    @rbac_rule_validation.action(
        service="neutron", rule="update_router")
    @decorators.idempotent_id('3d182f4e-0023-4218-9aa0-ea2b0ae0bd7a')
    def test_update_router(self):
        """Update Router

        RBAC test for the neutron update_router policy
        """
        new_name = data_utils.rand_name(
            self.__class__.__name__ + '-new-router-name')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(self.router['id'], name=new_name)

    @rbac_rule_validation.action(
        service="neutron", rule="update_router:external_gateway_info")
    @decorators.idempotent_id('5a6ae104-a9c3-4b56-8622-e1a0a0194474')
    def test_update_router_external_gateway_info(self):
        """Update Router External Gateway Info

        RBAC test for the neutron
        update_router:external_gateway_info policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(self.router['id'],
                                          external_gateway_info={})

    @rbac_rule_validation.action(
        service="neutron",
        rule="update_router:external_gateway_info:network_id")
    @decorators.idempotent_id('f1fc5a23-e3d8-44f0-b7bc-47006ad9d3d4')
    def test_update_router_external_gateway_info_network_id(self):
        """Update Router External Gateway Info Network Id

        RBAC test for the neutron
        update_router:external_gateway_info:network_id policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(
            self.router['id'],
            external_gateway_info={'network_id': self.network['id']})
        self.addCleanup(
            self.routers_client.update_router,
            self.router['id'],
            external_gateway_info=None)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @rbac_rule_validation.action(
        service="neutron",
        rule="update_router:external_gateway_info:enable_snat")
    @decorators.idempotent_id('515a2954-3d79-4695-aeb9-d1c222765840')
    def test_update_router_enable_snat(self):
        """Update Router External Gateway Info Enable Snat

        RBAC test for the neutron
        update_router:external_gateway_info:enable_snat policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(
            self.router['id'],
            external_gateway_info={'network_id': self.network['id'],
                                   'enable_snat': True})
        self.addCleanup(
            self.routers_client.update_router,
            self.router['id'],
            external_gateway_info=None)

    @rbac_rule_validation.action(
        service="neutron",
        rule="update_router:external_gateway_info:external_fixed_ips")
    @decorators.idempotent_id('f429e5ee-8f0a-4667-963e-72dd95d5adee')
    def test_update_router_external_fixed_ips(self):
        """Update Router External Gateway Info External Fixed Ips

        RBAC test for the neutron
        update_router:external_gateway_info:external_fixed_ips policy
        """
        unused_ip = self._get_unused_ip_address()
        external_fixed_ips = {'subnet_id': self.subnet['id'],
                              'ip_address': unused_ip}
        external_gateway_info = {'network_id': self.network['id'],
                                 'external_fixed_ips': [external_fixed_ips]}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(
            self.router['id'],
            external_gateway_info=external_gateway_info)
        self.addCleanup(
            self.routers_client.update_router,
            self.router['id'],
            external_gateway_info=None)

    @decorators.idempotent_id('ddc20731-dea1-4321-9abf-8772bf0b5977')
    @test.requires_ext(extension='l3-ha', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rule="update_router:ha")
    def test_update_high_availability_router(self):
        """Update high-availability router

        RBAC test for the neutron update_router:ha policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(self.router['id'], ha=True)
        self.addCleanup(self.routers_client.update_router, self.router['id'],
                        ha=False)

    @decorators.idempotent_id('e1932c19-8f73-41cd-b5d2-84c7ae5d530c')
    @test.requires_ext(extension='dvr', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rule="update_router:distributed")
    def test_update_distributed_router(self):
        """Update distributed router

        RBAC test for the neutron update_router:distributed policy
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.update_router(self.router['id'], distributed=True)
        self.addCleanup(self.routers_client.update_router, self.router['id'],
                        distributed=False)

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_router")
    @decorators.idempotent_id('c0634dd5-0467-48f7-a4ae-1014d8edb2a7')
    def test_delete_router(self):
        """Delete Router

        RBAC test for the neutron delete_router policy
        """
        router = self.create_router()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.delete_router(router['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="add_router_interface")
    @decorators.idempotent_id('a0627778-d68d-4913-881b-e345360cca19')
    def test_add_router_interface(self):
        """Add Router Interface

        RBAC test for the neutron add_router_interface policy
        """
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.routers_client.remove_router_interface,
            router['id'],
            subnet_id=subnet['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="remove_router_interface")
    @decorators.idempotent_id('ff2593a4-2bff-4c27-97d3-dd3702b27dfb')
    def test_remove_router_interface(self):
        """Remove Router Interface

        RBAC test for the neutron remove_router_interface policy
        """
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()

        self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.routers_client.remove_router_interface,
                        router['id'],
                        subnet_id=subnet['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.routers_client.remove_router_interface(
            router['id'],
            subnet_id=subnet['id'])
