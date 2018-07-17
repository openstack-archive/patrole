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

import netaddr

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


# TODO(gmann): Remove this test class once the nova queens branch goes
# into extended maintenance mode.
class FloatingIpsBulkRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36:
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#floating-ips-bulk-os-floating-ips-bulk-deprecated
    max_microversion = '2.35'
    depends_on_nova_network = True

    @classmethod
    def skip_checks(cls):
        super(FloatingIpsBulkRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-floating-ips-bulk', 'compute'):
            msg = "%s skipped as os-floating-ips-bulk extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")

    @classmethod
    def setup_clients(cls):
        super(FloatingIpsBulkRbacTest, cls).setup_clients()
        cls.fip_bulk_client = cls.os_primary.floating_ips_bulk_client

    @classmethod
    def resource_setup(cls):
        super(FloatingIpsBulkRbacTest, cls).resource_setup()
        cls.ip_range = CONF.validation.floating_ip_range
        cls.verify_unallocated_floating_ip_range(cls.ip_range)

    @classmethod
    def verify_unallocated_floating_ip_range(cls, ip_range):
        # Verify whether configure floating IP range is not already allocated.
        body = cls.fip_bulk_client.list_floating_ips_bulk()[
            'floating_ip_info']
        allocated_ips_list = map(lambda x: x['address'], body)
        for ip_addr in netaddr.IPNetwork(ip_range).iter_hosts():
            if str(ip_addr) in allocated_ips_list:
                msg = ("Configured unallocated floating IP range is already "
                       "allocated. Configure the correct unallocated range "
                       "as 'floating_ip_range'")
                raise lib_exc.InvalidConfiguration(msg)
        return

    def _create_floating_ips_bulk(self):
        pool = 'test_pool'
        # NOTE(felipemonteiro): Comment copied from Tempest. Reserving the IP
        # range but those are not attached anywhere. Using the below mentioned
        # interface which is not ever expected to be used. Clean up already
        # done for created IP range.
        interface = 'eth0'
        body = self.fip_bulk_client.create_floating_ips_bulk(
            self.ip_range, pool, interface)['floating_ips_bulk_create']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.fip_bulk_client.delete_floating_ips_bulk,
                        self.ip_range)
        return body

    @decorators.idempotent_id('9a49e73f-96a0-4e93-830a-22c4e443b486')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-floating-ips-bulk")
    def test_create_floating_ips_bulk(self):
        with self.rbac_utils.override_role(self):
            self._create_floating_ips_bulk()

    @decorators.idempotent_id('3b5c8a02-005d-4256-8a95-6fa2f389c6cf')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-floating-ips-bulk")
    def test_list_floating_ips_bulk(self):
        with self.rbac_utils.override_role(self):
            self.fip_bulk_client.list_floating_ips_bulk()

    @decorators.idempotent_id('37c2b759-c494-4e20-9dba-6a67b2df9573')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-floating-ips-bulk")
    def test_delete_floating_ips_bulk(self):
        self._create_floating_ips_bulk()
        with self.rbac_utils.override_role(self):
            self.fip_bulk_client.delete_floating_ips_bulk(self.ip_range)
