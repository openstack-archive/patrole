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

from tempest.common import utils
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class FloatingIpsBulkRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36:
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#floating-ips-bulk-os-floating-ips-bulk-deprecated
    max_microversion = '2.35'

    @classmethod
    def setup_clients(cls):
        super(FloatingIpsBulkRbacTest, cls).setup_clients()
        cls.fip_bulk_client = cls.os_primary.floating_ips_bulk_client

    @classmethod
    def skip_checks(cls):
        super(FloatingIpsBulkRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-floating-ips-bulk', 'compute'):
            msg = "%s skipped as os-floating-ips-bulk extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")

    @decorators.idempotent_id('3b5c8a02-005d-4256-8a95-6fa2f389c6cf')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-floating-ips-bulk")
    def test_list_floating_ips_bulk(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.fip_bulk_client.list_floating_ips_bulk()['floating_ip_info']
