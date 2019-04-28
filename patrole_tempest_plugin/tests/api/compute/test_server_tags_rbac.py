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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class ServerTagsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    min_microversion = '2.26'
    max_microversion = 'latest'

    @classmethod
    def skip_checks(cls):
        super(ServerTagsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-server-tags', 'compute'):
            msg = "os-server-tags extension is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources(network=True, subnet=True, router=True)
        super(ServerTagsRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(ServerTagsRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    def _add_tag_to_server(self):
        tag_name = data_utils.rand_name(self.__class__.__name__ + '-tag')
        self.servers_client.update_tag(self.server['id'], tag_name)
        self.addCleanup(self.servers_client.delete_all_tags, self.server['id'])
        return tag_name

    @decorators.idempotent_id('99e73dd3-adec-4044-b46c-84bdded35d09')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-tags:index"])
    def test_list_tags(self):
        with self.override_role():
            self.servers_client.list_tags(self.server['id'])

    @decorators.idempotent_id('9297c99e-94eb-429f-93cf-9b1838e33622')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-tags:show"])
    def test_check_tag_existence(self):
        tag_name = self._add_tag_to_server()
        with self.override_role():
            self.servers_client.check_tag_existence(self.server['id'],
                                                    tag_name)

    @decorators.idempotent_id('0d84ee94-d3ca-4635-8edf-b7f67ab8e4a3')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-tags:update"])
    def test_update_tag(self):
        with self.override_role():
            self._add_tag_to_server()

    @decorators.idempotent_id('115c2694-00aa-41ee-99f6-9eab4040c182')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-tags:delete"])
    def test_delete_tag(self):
        tag_name = self._add_tag_to_server()
        with self.override_role():
            self.servers_client.delete_tag(self.server['id'], tag_name)

    @decorators.idempotent_id('a8e19b87-6580-4bc8-9933-e62561ff667d')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-tags:update_all"])
    def test_update_all_tags(self):
        new_tag_name = data_utils.rand_name(self.__class__.__name__ + '-tag')
        with self.override_role():
            self.servers_client.update_all_tags(self.server['id'],
                                                [new_tag_name])

    @decorators.idempotent_id('89d51936-e333-42f9-a045-132a4865ba1a')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-tags:delete_all"])
    def test_delete_all_tags(self):
        with self.override_role():
            self.servers_client.delete_all_tags(self.server['id'])
