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
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ServerConsolesRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(ServerConsolesRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.console_output:
            raise cls.skipException('Console output not available.')

    @classmethod
    def resource_setup(cls):
        super(ServerConsolesRbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-console-output")
    @decorators.idempotent_id('90fd80f6-456c-11e7-a919-92ebcb67fe33')
    def test_get_console_output(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.get_console_output(self.server_id)


class ServerConsolesMaxV25RbacTest(rbac_base.BaseV2ComputeRbacTest):

    max_microversion = '2.5'

    @classmethod
    def skip_checks(cls):
        super(ServerConsolesMaxV25RbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.console_output:
            raise cls.skipException('Console output not available.')

    @classmethod
    def resource_setup(cls):
        super(ServerConsolesMaxV25RbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-remote-consoles")
    @decorators.idempotent_id('b0a72c02-9b15-4dcb-b186-efe8753370ab')
    def test_get_vnc_console_output(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.get_vnc_console(self.server_id, type="novnc")


class ServerConsolesV26RbacTest(rbac_base.BaseV2ComputeRbacTest):

    min_microversion = '2.6'
    max_microversion = 'latest'

    @classmethod
    def skip_checks(cls):
        super(ServerConsolesV26RbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.console_output:
            raise cls.skipException('Console output not available.')

    @classmethod
    def resource_setup(cls):
        super(ServerConsolesV26RbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-remote-consoles")
    @decorators.idempotent_id('879597de-87e0-4da9-a60a-28c8088dc508')
    def test_get_remote_console_output(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.get_remote_console(self.server_id,
                                               "novnc", "vnc")
