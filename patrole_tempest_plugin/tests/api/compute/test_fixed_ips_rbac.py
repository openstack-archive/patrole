#    Copyright 2017 NEC Corporation.
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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class FixedIpsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests will fail with a 404 starting from microversion 2.36:
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#fixed-ips-os-fixed-ips-deprecated
    max_microversion = '2.35'

    @classmethod
    def skip_checks(cls):
        super(FixedIpsRbacTest, cls).skip_checks()
        if CONF.service_available.neutron:
            msg = ("%s skipped as neutron is available" % cls.__name__)
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(FixedIpsRbacTest, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE')
        server = cls.servers_client.show_server(server['id'])['server']
        cls.ip = None
        for ip_set in server['addresses']:
            for ip in server['addresses'][ip_set]:
                if ip['OS-EXT-IPS:type'] == 'fixed':
                    cls.ip = ip['addr']
                    break
            if cls.ip:
                break
        if cls.ip is None:
            raise cls.skipException("No fixed ip found for server: %s"
                                    % server['id'])

    @decorators.idempotent_id('c89391f7-4844-4a70-a116-37c1336efb99')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-fixed-ips"])
    def test_show_fixed_ip_details(self):
        with self.override_role():
            self.fixed_ips_client.show_fixed_ip(self.ip)

    @decorators.idempotent_id('f0314501-735d-4315-9856-959e01e82f0d')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-fixed-ips"])
    def test_set_reserve(self):
        with self.override_role():
            self.fixed_ips_client.reserve_fixed_ip(self.ip, reserve="None")

    @decorators.idempotent_id('866a6fdc-a237-4502-9bf2-52fe82aba356')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-fixed-ips"])
    def test_set_unreserve(self):
        with self.override_role():
            self.fixed_ips_client.reserve_fixed_ip(self.ip, unreserve="None")
