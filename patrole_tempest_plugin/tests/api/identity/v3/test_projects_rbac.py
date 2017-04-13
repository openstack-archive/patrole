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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base


class IdentityProjectV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d904')
    def test_create_project(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.setup_test_project()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d905')
    def test_update_project(self):
        project = self.setup_test_project()
        new_desc = data_utils.rand_name('description')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.projects_client.update_project(project['id'],
                                            description=new_desc)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d906')
    def test_delete_project(self):
        project = self.setup_test_project()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.projects_client.delete_project(project['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d907')
    def test_show_project(self):
        project = self.setup_test_project()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.projects_client.show_project(project['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_projects")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d908')
    def test_list_projects(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.projects_client.list_projects()
