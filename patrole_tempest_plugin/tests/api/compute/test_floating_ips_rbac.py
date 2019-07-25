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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class FloatingIpsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36:
    # See the following link for details:
    # https://docs.openstack.org/api-ref/compute/#floating-ips-os-floating-ips-deprecated
    max_microversion = '2.35'

    @classmethod
    def skip_checks(cls):
        super(FloatingIpsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-floating-ips', 'compute'):
            msg = "%s skipped as os-floating-ips extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")

    @decorators.idempotent_id('ac1b3053-f755-4cda-85a0-30e88b88d7ba')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-floating-ips"])
    def test_list_floating_ips(self):
        with self.override_role():
            self.floating_ips_client.list_floating_ips()

    @decorators.idempotent_id('bebe52b3-5269-4e72-80c8-5a4a39c3bfa6')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-floating-ips"])
    def test_show_floating_ip(self):
        body = self.floating_ips_client.create_floating_ip(
            pool=CONF.network.floating_network_name)['floating_ip']
        self.addCleanup(
            self.floating_ips_client.delete_floating_ip, body['id'])
        with self.override_role():
            self.floating_ips_client.show_floating_ip(body['id'])

    @decorators.idempotent_id('2bfb8745-c329-4ee9-95f6-c165a1989dbf')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-floating-ips"])
    def test_create_floating_ips(self):
        with self.override_role():
            body = self.floating_ips_client.create_floating_ip(
                pool=CONF.network.floating_network_name)['floating_ip']
        self.addCleanup(
            self.floating_ips_client.delete_floating_ip, body['id'])

    @decorators.idempotent_id('d3028373-5027-4e7a-b761-01c515403ecb')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-floating-ips"])
    def test_delete_floating_ip(self):
        body = self.floating_ips_client.create_floating_ip(
            pool=CONF.network.floating_network_name)['floating_ip']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.floating_ips_client.delete_floating_ip, body['id'])
        with self.override_role():
            self.floating_ips_client.delete_floating_ip(body['id'])
