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
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class IpsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(IpsRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-ips', 'compute'):
            msg = "%s skipped as os-ips not enabled." % cls.__name__
            raise cls.skipException(msg)
        if not CONF.service_available.neutron:
            raise cls.skipException(
                '%s skipped as Neutron is required' % cls.__name__)

    @classmethod
    def setup_credentials(cls):
        cls.prepare_instance_network()
        super(IpsRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(IpsRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    @decorators.idempotent_id('6886d360-0d86-4760-b1a3-882d81fbebcc')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:ips:index")
    def test_list_addresses(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_addresses(self.server['id'])['addresses']

    @decorators.idempotent_id('fa43e7e5-0db9-48eb-9c6b-c11eb766b8e4')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:ips:show")
    def test_list_addresses_by_network(self):
        addresses = self.servers_client.list_addresses(
            self.server['id'])['addresses']
        address = next(iter(addresses))
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_addresses_by_network(
            self.server['id'], address)[address]
