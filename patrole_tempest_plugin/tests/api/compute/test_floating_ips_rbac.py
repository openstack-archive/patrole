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


class FloatingIpsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36:
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#floating-ips-os-floating-ips-deprecated
    min_microversion = '2.10'
    max_microversion = '2.35'

    @classmethod
    def setup_clients(cls):
        super(FloatingIpsRbacTest, cls).setup_clients()
        cls.client = cls.floating_ips_client

    @classmethod
    def skip_checks(cls):
        super(FloatingIpsRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-floating-ips', 'compute'):
            msg = "%s skipped as os-floating-ips extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)

    @decorators.idempotent_id('ac1b3053-f755-4cda-85a0-30e88b88d7ba')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-floating-ips")
    def test_list_floating_ips(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_floating_ips()['floating_ips']
