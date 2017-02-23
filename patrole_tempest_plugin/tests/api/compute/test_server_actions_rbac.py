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
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ServerActionsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(ServerActionsRbacTest, self).tearDown()

    @classmethod
    def setup_clients(cls):
        super(ServerActionsRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def skip_checks(cls):
        super(ServerActionsRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)
        if not CONF.compute_feature_enabled.interface_attach:
            raise cls.skipException(
                '%s skipped as interface attachment is not available'
                % cls.__name__)

    @classmethod
    def resource_setup(cls):
        cls.set_validation_resources()
        super(ServerActionsRbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE',
                                               validatable=True)['id']

    def _test_start_server(self):
        self.client.start_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'ACTIVE')

    def _test_stop_server(self):
        self.client.stop_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'SHUTOFF')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:stop")
    @decorators.idempotent_id('ab4a17d2-166f-4a6d-9944-f17baa576cf2')
    def test_stop_server(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._test_stop_server()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:start")
    @decorators.idempotent_id('8876bfa9-4d10-406e-a335-a57e451abb12')
    def test_start_server(self):
        self._test_stop_server()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._test_start_server()
