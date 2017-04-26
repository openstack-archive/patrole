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
from patrole_tempest_plugin.tests.api.identity.v2 import rbac_base

CONF = config.CONF


class IdentityRoleV2RbacTest(rbac_base.BaseIdentityV2RbacTest):

    @classmethod
    def setup_clients(cls):
        super(IdentityRoleV2RbacTest, cls).setup_clients()
        cls.roles_client = cls.os_primary.roles_client

    def _create_role(self):
        role = self.roles_client.create_role(
            name=data_utils.rand_name('test_role'))['role']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role, role['id'])
        return role

    def _create_tenant_user_and_role(self):
        tenant = self._create_tenant()
        user = self._create_user(tenantid=tenant['id'])
        role = self._create_role()
        return tenant, user, role

    def _create_role_on_project(self, tenant, user, role):
        self.roles_client.create_user_role_on_project(
            tenant['id'], user['id'], role['id'])
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.roles_client.delete_role_from_user_on_project,
            tenant['id'], user['id'], role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_role",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d904')
    def test_create_role(self):

        """Create Role Test

        RBAC test for Identity v2 role-create
        """

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_role()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_role",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d905')
    def test_delete_role(self):

        """Delete Role Test

        RBAC test for Identity v2 delete_role
        """
        role = self._create_role()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.roles_client.delete_role(role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_role",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d906')
    def test_show_role(self):

        """Get Role Test

        RBAC test for Identity v2 show_role
        """
        role = self._create_role()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.roles_client.show_role(role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_roles",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d907')
    def test_list_roles(self):

        """List Roles Test

        RBAC test for Identity v2 list_roles
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.roles_client.list_roles()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:add_role_to_user",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d908')
    def test_create_role_on_project(self):

        """Assign User Role Test

        RBAC test for Identity v2 create_user_role_on_project
        """
        tenant, user, role = self._create_tenant_user_and_role()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_role_on_project(tenant, user, role)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:remove_role_from_user",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d909')
    def test_delete_role_from_user_on_project(self):

        """Remove User Roles Test

        RBAC test for Identity v2 delete_role_from_user_on_project
        """
        tenant, user, role = self._create_tenant_user_and_role()
        self._create_role_on_project(tenant, user, role)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.roles_client.delete_role_from_user_on_project(
            tenant['id'], user['id'], role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_user_roles",
                                 admin_only=True)
    @decorators.idempotent_id('0f148510-63bf-11e6-8674-080044d0d90a')
    def test_list_user_roles_on_project(self):

        """List User Roles Test

        RBAC test for Identity v2 list_user_roles_on_project
        """
        tenant = self._create_tenant()
        user = self._create_user(tenantid=tenant['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.roles_client.list_user_roles_on_project(
            tenant['id'], user['id'])
