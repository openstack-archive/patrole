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
#

import netaddr

from oslo_log import log

from tempest.common.utils import net_utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base

CONF = config.CONF
LOG = log.getLogger(__name__)


class PortsRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def resource_setup(cls):
        super(PortsRbacTest, cls).resource_setup()
        cls.network = cls.create_network()

        # Create a subnet by admin user
        cls.cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)

        cls.subnet = cls.create_subnet(cls.network, cidr=cls.cidr,
                                       mask_bits=24)
        cls.ip_range = netaddr.IPRange(
            cls.subnet['allocation_pools'][0]['start'],
            cls.subnet['allocation_pools'][0]['end'])

        # Create a port by admin user
        body = cls.ports_client.create_port(network_id=cls.network['id'])
        cls.port = body['port']
        cls.ports.append(cls.port)
        ipaddr = cls.port['fixed_ips'][0]['ip_address']
        cls.port_ip_address = ipaddr
        cls.port_mac_address = cls.port['mac_address']

    def _create_port(self, **post_body):

        body = self.ports_client.create_port(**post_body)
        port = body['port']

        # Schedule port deletion with verification upon test completion
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.ports_client.delete_port,
                        port['id'])

        return port

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_port")
    @decorators.idempotent_id('0ec8c551-625c-4864-8a52-85baa7c40f22')
    def test_create_port(self):

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        post_body = {'network_id': self.network['id']}
        self._create_port(**post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_port:binding:host_id")
    @decorators.idempotent_id('a54bd6b8-a7eb-4101-bfe8-093930b0d660')
    def test_create_port_binding_host_id(self):

        post_body = {'network_id': self.network['id'],
                     'binding:host_id': "rbac_test_host"}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_port(**post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_port:fixed_ips")
    @decorators.idempotent_id('2551e10d-006a-413c-925a-8c6f834c09ac')
    def test_create_port_fixed_ips(self):

        # Pick an unused ip address.
        ip_list = net_utils.get_unused_ip_addresses(self.ports_client,
                                                    self.subnets_client,
                                                    self.network['id'],
                                                    self.subnet['id'],
                                                    1)
        fixed_ips = [{'ip_address': ip_list[0]},
                     {'subnet_id': self.subnet['id']}]

        post_body = {'network_id': self.network['id'],
                     'fixed_ips': fixed_ips}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_port(**post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_port:mac_address")
    @decorators.idempotent_id('aee6d0be-a7f3-452f-aefc-796b4eb9c9a8')
    def test_create_port_mac_address(self):

        post_body = {'network_id': self.network['id'],
                     'mac_address': data_utils.rand_mac_address()}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_port(**post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_port:binding:profile")
    @decorators.idempotent_id('98fa38ab-c2ed-46a0-99f0-59f18cbd257a')
    def test_create_port_binding_profile(self):

        binding_profile = {"foo": "1"}

        post_body = {'network_id': self.network['id'],
                     'binding:profile': binding_profile}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_port(**post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_port:allowed_address_pairs")
    @decorators.idempotent_id('b638d1f4-d903-4ca8-aa2a-6fd603c5ec3a')
    def test_create_port_allowed_address_pairs(self):

        # Create port with allowed address pair attribute
        allowed_address_pairs = [{'ip_address': self.port_ip_address,
                                  'mac_address': self.port_mac_address}]

        post_body = {'network_id': self.network['id'],
                     'allowed_address_pairs': allowed_address_pairs}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_port(**post_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_port",
                                 expected_error_code=404)
    @decorators.idempotent_id('a9d41cb8-78a2-4b97-985c-44e4064416f4')
    def test_show_port(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.show_port(self.port['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_port:binding:vif_type")
    @decorators.idempotent_id('125aff0b-8fed-4f8e-8410-338616594b06')
    def test_show_port_binding_vif_type(self):

        # Verify specific fields of a port
        fields = ['binding:vif_type']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        retrieved_port = self.ports_client.show_port(
            self.port['id'], fields=fields)['port']

        # Rather than throwing a 403, the field is not present, so raise exc.
        if fields[0] not in retrieved_port:
            raise rbac_exceptions.RbacActionFailed

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_port:binding:vif_details")
    @decorators.idempotent_id('e42bfd77-fcce-45ee-9728-3424300f0d6f')
    def test_show_port_binding_vif_details(self):

        # Verify specific fields of a port
        fields = ['binding:vif_details']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        retrieved_port = self.ports_client.show_port(
            self.port['id'], fields=fields)['port']

        # Rather than throwing a 403, the field is not present, so raise exc.
        if fields[0] not in retrieved_port:
            raise rbac_exceptions.RbacActionFailed

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_port:binding:host_id")
    @decorators.idempotent_id('8e61bcdc-6f81-443c-833e-44410266551e')
    def test_show_port_binding_host_id(self):

        # Verify specific fields of a port
        fields = ['binding:host_id']
        post_body = {'network_id': self.network['id'],
                     'binding:host_id': data_utils.rand_name('host-id')}
        port = self._create_port(**post_body)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        retrieved_port = self.ports_client.show_port(
            port['id'], fields=fields)['port']

        # Rather than throwing a 403, the field is not present, so raise exc.
        if fields[0] not in retrieved_port:
            raise rbac_exceptions.RbacActionFailed

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_port:binding:profile")
    @decorators.idempotent_id('d497cea9-c4ad-42e0-acc9-8d257d6b01fc')
    def test_show_port_binding_profile(self):

        # Verify specific fields of a port
        fields = ['binding:profile']
        binding_profile = {"foo": "1"}
        post_body = {'network_id': self.network['id'],
                     'binding:profile': binding_profile}
        port = self._create_port(**post_body)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        retrieved_port = self.ports_client.show_port(
            port['id'], fields=fields)['port']

        # Rather than throwing a 403, the field is not present, so raise exc.
        if fields[0] not in retrieved_port:
            raise rbac_exceptions.RbacActionFailed

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port")
    @decorators.idempotent_id('afa80981-3c59-42fd-9531-3bcb2cd03711')
    def test_update_port(self):

        port = self.create_port(self.network)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(port['id'], admin_state_up=False)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port:mac_address")
    @decorators.idempotent_id('507140c8-7b14-4d63-b627-2103691d887e')
    def test_update_port_mac_address(self):

        port = self.create_port(self.network)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(
            port['id'],
            mac_address=data_utils.rand_mac_address())

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port:fixed_ips")
    @decorators.idempotent_id('c091c825-532b-4c6f-a14f-affd3259c1c3')
    def test_update_port_fixed_ips(self):

        # Pick an ip address within the allocation_pools range.
        post_body = {'network_id': self.network['id']}
        port = self._create_port(**post_body)

        # Pick an unused ip address.
        ip_list = net_utils.get_unused_ip_addresses(self.ports_client,
                                                    self.subnets_client,
                                                    self.network['id'],
                                                    self.subnet['id'],
                                                    1)
        fixed_ips = [{'ip_address': ip_list[0]}]

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(port['id'],
                                      fixed_ips=fixed_ips)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port:port_security_enabled")
    @decorators.idempotent_id('795541af-6652-4e35-9581-fd58224f7545')
    def test_update_port_security_enabled(self):

        port = self.create_port(self.network)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(port['id'],
                                      security_groups=[])

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port:binding:host_id")
    @decorators.idempotent_id('24206a72-0d90-4712-918c-5c9a1ebef64d')
    def test_update_port_binding_host_id(self):

        post_body = {'network_id': self.network['id'],
                     'binding:host_id': 'rbac_test_host'}
        port = self._create_port(**post_body)

        updated_body = {'port_id': port['id'],
                        'binding:host_id': 'rbac_test_host_updated'}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(**updated_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port:binding:profile")
    @decorators.idempotent_id('990ea8d1-9257-4f71-a3bf-d6d0914625c5')
    def test_update_port_binding_profile(self):

        binding_profile = {"foo": "1"}
        post_body = {'network_id': self.network['id'],
                     'binding:profile': binding_profile}

        port = self._create_port(**post_body)

        new_binding_profile = {"foo": "2"}
        updated_body = {'port_id': port['id'],
                        'binding:profile': new_binding_profile}

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(**updated_body)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_port:allowed_address_pairs")
    @decorators.idempotent_id('729c2151-bb49-4f4f-9d58-3ed8819b7582')
    def test_update_port_allowed_address_pairs(self):

        # Pick an unused ip address.
        ip_list = net_utils.get_unused_ip_addresses(self.ports_client,
                                                    self.subnets_client,
                                                    self.network['id'],
                                                    self.subnet['id'],
                                                    1)
        # Update allowed address pair attribute of port
        address_pairs = [{'ip_address': ip_list[0],
                          'mac_address': data_utils.rand_mac_address()}]
        post_body = {'network_id': self.network['id']}
        port = self._create_port(**post_body)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.update_port(port['id'],
                                      allowed_address_pairs=address_pairs)

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_port",
                                 expected_error_code=404)
    @decorators.idempotent_id('1cf8e582-bc09-46cb-b32a-82bf991ad56f')
    def test_delete_port(self):

        port = self._create_port(network_id=self.network['id'])
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.ports_client.delete_port(port['id'])
