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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class HostsRbacTest(rbac_base.BaseV2ComputeRbacTest):
    # These tests will fail with a 404 starting from microversion 2.43:
    # See the following links for details:
    # https://developer.openstack.org/api-ref/compute/#hosts-os-hosts-deprecated
    max_microversion = '2.42'

    @classmethod
    def skip_checks(cls):
        super(HostsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-hosts', 'compute'):
            msg = "%s skipped as os-hosts not enabled." % cls.__name__
            raise cls.skipException(msg)

    @decorators.idempotent_id('035b7935-2fae-4218-8d37-27fa83097494')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-hosts")
    def test_list_hosts(self):
        with self.rbac_utils.override_role(self):
            self.hosts_client.list_hosts()

    @decorators.idempotent_id('bc10d8b4-d2c3-4d4e-9d2b-31d1bd3e1b51')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-hosts")
    def test_show_host_details(self):
        hosts = self.hosts_client.list_hosts()['hosts']
        hosts = [host for host in hosts if host['service'] == 'compute']
        self.assertNotEmpty(hosts)

        with self.rbac_utils.override_role(self):
            self.hosts_client.show_host(hosts[0]['host_name'])
