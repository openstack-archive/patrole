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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class HostsAdminRbacTest(rbac_base.BaseV2ComputeAdminRbacTest):

    @classmethod
    def setup_clients(cls):
        super(HostsAdminRbacTest, cls).setup_clients()
        cls.client = cls.os.hosts_client

    @classmethod
    def skip_checks(cls):
        super(HostsAdminRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(HostsAdminRbacTest, self).tearDown()

    @decorators.idempotent_id('035b7935-2fae-4218-8d37-27fa83097494')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-hosts")
    def test_list_hosts(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_hosts()['hosts']
