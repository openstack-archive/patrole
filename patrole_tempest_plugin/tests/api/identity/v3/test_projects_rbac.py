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

from tempest.common.utils import data_utils
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base

CONF = config.CONF


class IdentityProjectV3AdminRbacTest(
        rbac_base.BaseIdentityV3RbacAdminTest):

    def tearDown(self):
        """Reverts user back to admin for cleanup."""
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentityProjectV3AdminRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d904')
    def test_create_project(self):
        """Create a Project.

        RBAC test for Keystone: identity:create_project
        """
        name = data_utils.rand_name('project')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        project = self.non_admin_projects_client \
                      .create_project(name)['project']
        self.addCleanup(self.projects_client.delete_project, project['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d905')
    def test_update_project(self):
        """Update a Project.

        RBAC test for Keystone: identity:update_project
        """
        project = self._setup_test_project()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_projects_client \
            .update_project(project['id'],
                            description="Changed description")

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d906')
    def test_delete_project(self):
        """Delete a Project.

        RBAC test for Keystone: identity:delete_project
        """
        project = self._setup_test_project()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_projects_client.delete_project(project['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d907')
    def test_show_project(self):
        """Show a project.

        RBAC test for Keystone: identity:get_project
        """
        project = self._setup_test_project()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_projects_client.show_project(project['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_projects")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d908')
    def test_list_projects(self):
        """List all projects.

        RBAC test for Keystone: identity:list_projects
        """
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_projects_client.list_projects()
