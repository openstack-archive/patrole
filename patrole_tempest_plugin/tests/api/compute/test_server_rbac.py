# Copyright 2017 AT&T Corporation.
# All Rights Reserved.
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

from oslo_log import log

from tempest.common import waiters

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base as base

LOG = log.getLogger(__name__)


class ComputeServersRbacTest(base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ComputeServersRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:create")
    @decorators.idempotent_id('4f34c73a-6ddc-4677-976f-71320fa855bd')
    def test_create_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.create_test_server(wait_until='ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:delete")
    @decorators.idempotent_id('062e3440-e873-4b41-9317-bf6d8be50c12')
    def test_delete_server(self):
        server = self.create_test_server(wait_until='ACTIVE')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:update")
    @decorators.idempotent_id('077b17cb-5621-43b9-8adf-5725f0d7a863')
    def test_update_server(self):
        server = self.create_test_server(wait_until='ACTIVE')
        new_name = data_utils.rand_name('server')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.client.update_server(server['id'], name=new_name)
        except exceptions.ServerFault as e:
            # Some other policy may have blocked it.
            LOG.info("ServerFault exception caught. Some other policy "
                     "blocked updating of server")
            raise rbac_exceptions.RbacActionFailed(e)
