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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class ServerMetadataRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def resource_setup(cls):
        super(ServerMetadataRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(metadata={}, wait_until='ACTIVE')
        cls.meta = {'default_key': 'value1', 'delete_key': 'value2'}

    def setUp(self):
        super(ServerMetadataRbacTest, self).setUp()
        self.servers_client.set_server_metadata(self.server['id'], self.meta)[
            'metadata']

    @decorators.idempotent_id('b07bbc27-58e2-4581-869d-ad228cec5d9a')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:server-metadata:index")
    def test_list_server_metadata(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.list_server_metadata(self.server['id'])

    @decorators.idempotent_id('6e76748b-2417-4fa2-b41a-c0cc4bff356b')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:server-metadata:update_all")
    def test_set_server_metadata(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.set_server_metadata(self.server['id'], {})

    @decorators.idempotent_id('1060bac4-fe16-4a77-be64-d8e482a06eab')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:server-metadata:create")
    def test_update_server_metadata(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.update_server_metadata(self.server['id'], {})

    @decorators.idempotent_id('93dd8323-d3fa-48d1-8bd6-91c1b62fc341')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:server-metadata:show")
    def test_show_server_metadata_item(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.show_server_metadata_item(
                self.server['id'], 'default_key')

    @decorators.idempotent_id('79511293-4bd7-447d-ba7e-634d0f4da70c')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:server-metadata:update")
    def test_set_server_metadata_item(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.set_server_metadata_item(
                self.server['id'], 'default_key', {'default_key': 'value2'})

    @decorators.idempotent_id('feec5064-678d-40bc-a88f-c856e18d1e31')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:server-metadata:delete")
    def test_delete_server_metadata_item(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.delete_server_metadata_item(
                self.server['id'], 'delete_key')
