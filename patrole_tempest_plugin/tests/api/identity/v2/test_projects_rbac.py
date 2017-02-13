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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.identity.v2 import rbac_base

CONF = config.CONF


class IdentityProjectV2AdminRbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentityProjectV2AdminRbacTest, self).tearDown()

    @classmethod
    def setup_clients(cls):
        super(IdentityProjectV2AdminRbacTest, cls).setup_clients()
        cls.tenants_client = cls.os.tenants_client

    def _create_tenant(self, name):
        self.tenant = self.tenants_client.create_tenant(name=name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.tenants_client.delete_tenant,
                        self.tenant['tenant']['id'])
        return self.tenant

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080044d0d904')
    def test_create_project(self):

        """Create Project Test

        RBAC test for Identity 2.0 create_tenant
        """

        tenant_name = data_utils.rand_name('test_create_project')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_tenant(tenant_name)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080044d0d905')
    def test_update_project(self):

        """Update Project Test

        RBAC test for Identity 2.0 update_tenant
        """

        tenant_name = data_utils.rand_name('test_update_project')
        tenant = self._create_tenant(tenant_name)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.tenants_client.update_tenant(tenant['tenant']['id'],
                                          description="Changed description")

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080044d0d906')
    def test_delete_project(self):

        """Delete Project Test

        RBAC test for Identity 2.0 delete_tenant
        """

        tenant_name = data_utils.rand_name('test_delete_project')
        tenant = self._create_tenant(tenant_name)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.tenants_client.delete_tenant(tenant['tenant']['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_project")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080044d0d907')
    def test_get_project(self):

        """Get Project Test

        RBAC test for Identity 2.0 show_tenant
        """

        tenant_name = data_utils.rand_name('test_get_project')
        tenant = self._create_tenant(tenant_name)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.tenants_client.show_tenant(tenant['tenant']['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_projects")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080044d0d908')
    def test_get_all_projects(self):

        """List All Projects Test

        RBAC test for Identity 2.0 list_tenants
        """

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.tenants_client.list_tenants()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_user_projects")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080044d0d909')
    def test_list_users_for_tenant(self):

        """Get Users of a Project Test

        RBAC test for Identity 2.0 list_tenant_users
        """

        tenant_name = data_utils.rand_name('test_list_users_for_tenant')
        tenant = self._create_tenant(tenant_name)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.tenants_client.list_tenant_users(tenant['tenant']['id'])
