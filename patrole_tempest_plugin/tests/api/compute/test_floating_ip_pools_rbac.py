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


class FloatingIpPoolsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36:
    # See the following link for details:
    # https://docs.openstack.org/api-ref/compute/#floating-ip-pools-os-floating-ip-pools-deprecated
    max_microversion = '2.35'

    @classmethod
    def setup_clients(cls):
        super(FloatingIpPoolsRbacTest, cls).setup_clients()
        cls.fip_pools_client = cls.os_primary.floating_ip_pools_client

    @classmethod
    def skip_checks(cls):
        super(FloatingIpPoolsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-floating-ip-pools', 'compute'):
            msg = "%s skipped as os-floating-ip-pools extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")

    @decorators.idempotent_id('c1a17153-b25d-4444-a721-5897d7737482')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-floating-ip-pools"])
    def test_list_floating_ip_pools(self):
        with self.override_role():
            self.fip_pools_client.list_floating_ip_pools()
