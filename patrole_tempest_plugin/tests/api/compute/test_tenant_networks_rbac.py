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

from tempest.common import utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class TenantNetworksRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36.
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#project-networks-os-tenant-networks-deprecated
    max_microversion = '2.35'

    @classmethod
    def setup_clients(cls):
        super(TenantNetworksRbacTest, cls).setup_clients()
        cls.tenant_networks_client = cls.os_primary.tenant_networks_client

    @classmethod
    def skip_checks(cls):
        super(TenantNetworksRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-tenant-networks', 'compute'):
            msg = "os-tenant-networks extension not enabled."
            raise cls.skipException(msg)
        if not CONF.service_available.neutron:
            raise cls.skipException(
                '%s skipped as Neutron is required' % cls.__name__)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources(network=True)
        super(TenantNetworksRbacTest, cls).setup_credentials()

    @decorators.idempotent_id('42b39ba1-14aa-4799-9518-34367d0da67a')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-tenant-networks"])
    def test_list_show_tenant_networks(self):
        with self.override_role():
            self.tenant_networks_client.list_tenant_networks()
