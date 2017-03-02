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

from tempest.common import waiters
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class SuspendServerRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(SuspendServerRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def skip_checks(cls):
        super(SuspendServerRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.suspend:
            msg = "%s skipped as suspend compute feature is not available." \
                  % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(SuspendServerRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)

        # Guarantee that the server is active during each test run.
        vm_state = self.client.show_server(self.server['id'])['server'][
            'OS-EXT-STS:vm_state'].upper()
        if vm_state != 'ACTIVE':
            self.client.resume_server(self.server['id'])
            waiters.wait_for_server_status(self.client, self.server['id'],
                                           'ACTIVE')

        super(SuspendServerRbacTest, self).tearDown()

    @decorators.idempotent_id('b775930f-237c-431c-83ae-d33ed1b9700b')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-suspend-server:suspend")
    def test_suspend_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.suspend_server(self.server['id'])
        waiters.wait_for_server_status(self.client, self.server['id'],
                                       'SUSPENDED')

    @decorators.idempotent_id('4d90bd02-11f8-45b1-a8a1-534665584675')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-suspend-server:resume")
    def test_resume_server(self):
        self.client.suspend_server(self.server['id'])
        waiters.wait_for_server_status(self.client, self.server['id'],
                                       'SUSPENDED')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.resume_server(self.server['id'])
        waiters.wait_for_server_status(self.client,
                                       self.server['id'],
                                       'ACTIVE')
