# Copyright 2018 AT&T Corporation.
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base

CONF = config.CONF


class ProjectTagsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def skip_checks(cls):
        super(ProjectTagsV3RbacTest, cls).skip_checks()
        if not CONF.identity_feature_enabled.project_tags:
            raise cls.skipException("Project tags feature disabled")

    @classmethod
    def resource_setup(cls):
        super(ProjectTagsV3RbacTest, cls).resource_setup()
        cls.project_id = cls.setup_test_project()['id']

    def tearDown(self):
        self.project_tags_client.delete_all_project_tags(self.project_id)
        super(ProjectTagsV3RbacTest, self).tearDown()

    @decorators.idempotent_id('acbd7b2d-0a4d-4990-9fab-eccad69d4238')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_project_tag")
    def test_update_project_tag(self):
        tag = data_utils.rand_name(self.__class__.__name__ + '-Tag')
        with self.rbac_utils.override_role(self):
            self.project_tags_client.update_project_tag(self.project_id, tag)

    @decorators.idempotent_id('e122d7d1-bb6d-43af-b489-afa8c609b9ae')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_project_tags")
    def test_list_project_tags(self):
        with self.rbac_utils.override_role(self):
            self.project_tags_client.list_project_tags(self.project_id)

    @decorators.idempotent_id('716f9081-4626-4594-a82c-e7dc037464ac')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_project_tags")
    def test_update_all_project_tags(self):
        tags = [
            data_utils.rand_name(self.__class__.__name__ + '-Tag')
            for _ in range(2)
        ]
        with self.rbac_utils.override_role(self):
            self.project_tags_client.update_all_project_tags(
                self.project_id, tags)

    @decorators.idempotent_id('974cb1da-d7d4-4863-99da-4a3f0c801729')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_project_tag")
    def test_check_project_tag_existence(self):
        tag = data_utils.rand_name(self.__class__.__name__ + '-Tag')
        self.project_tags_client.update_project_tag(self.project_id, tag)

        with self.rbac_utils.override_role(self):
            self.project_tags_client.check_project_tag_existence(
                self.project_id, tag)

    @decorators.idempotent_id('ffe0c8e1-f9eb-43c5-8097-1e938fc08e07')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_project_tag")
    def test_delete_project_tag(self):
        tag = data_utils.rand_name(self.__class__.__name__ + '-Tag')
        self.project_tags_client.update_project_tag(self.project_id, tag)

        with self.rbac_utils.override_role(self):
            self.project_tags_client.delete_project_tag(self.project_id, tag)

    @decorators.idempotent_id('94d0ef63-e9e3-4287-9c5e-bd5464467d77')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_project_tags")
    def test_delete_all_project_tags(self):
        with self.rbac_utils.override_role(self):
            self.project_tags_client.delete_all_project_tags(self.project_id)
