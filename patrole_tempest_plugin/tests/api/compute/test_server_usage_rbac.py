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

from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class ServerUsageRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(ServerUsageRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('OS-SRV-USG', 'compute'):
            msg = "%s skipped as OS-SRV-USG not enabled." % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(ServerUsageRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-usage")
    @decorators.idempotent_id('f0437ead-b9fb-462a-9f3d-ce53fac9d57a')
    def test_show_server_diagnostics(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_server(self.server['id'])
