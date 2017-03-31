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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base


class IdentityRolesV3AdminRbacTest(rbac_base.BaseIdentityV3RbacAdminTest):

    @classmethod
    def resource_setup(cls):
        super(IdentityRolesV3AdminRbacTest, cls).resource_setup()
        cls.domain = cls.setup_test_domain()
        cls.project = cls.setup_test_project()
        cls.group = cls.setup_test_group()
        cls.role = cls.setup_test_role()
        cls.user = cls.setup_test_user()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_role")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d904')
    def test_create_role(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.setup_test_role()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_role")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d905')
    def test_update_role(self):
        new_role_name = data_utils.rand_name('test_update_role')

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.update_role(self.role['id'],
                                      name=new_role_name)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_role")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d906')
    def test_delete_role(self):
        role = self.setup_test_role()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.delete_role(role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_role")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d907')
    def test_show_role(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.show_role(self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_roles")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d908')
    def test_list_roles(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.list_roles()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d909')
    def test_create_user_role_on_project(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.create_user_role_on_project(
            self.project['id'],
            self.user['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_user_on_project,
                        self.project['id'],
                        self.user['id'],
                        self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:check_grant")
    @decorators.idempotent_id('22921b1e-1a33-4026-bff9-f236d6dd149c')
    def test_check_user_role_existence_on_project(self):
        self.roles_client.create_user_role_on_project(
            self.project['id'],
            self.user['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_user_on_project,
                        self.project['id'],
                        self.user['id'],
                        self.role['id'])

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.check_user_role_existence_on_project(
            self.project['id'],
            self.user['id'],
            self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:revoke_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90a')
    def test_delete_role_from_user_on_project(self):
        self.roles_client.create_user_role_on_project(
            self.project['id'],
            self.user['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_user_on_project,
                        self.project['id'],
                        self.user['id'],
                        self.role['id'])

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.delete_role_from_user_on_project(
            self.project['id'],
            self.user['id'],
            self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_grants")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90b')
    def test_list_user_roles_on_project(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.list_user_roles_on_project(
            self.project['id'],
            self.user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90c')
    def test_create_group_role_on_project(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.create_group_role_on_project(
            self.project['id'],
            self.group['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_project,
                        self.project['id'],
                        self.group['id'],
                        self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:revoke_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90d')
    def test_delete_role_from_group_on_project(self):
        self.roles_client.create_group_role_on_project(
            self.project['id'],
            self.group['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_project,
                        self.project['id'],
                        self.group['id'],
                        self.role['id'])

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.delete_role_from_group_on_project(
            self.project['id'],
            self.group['id'],
            self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_grants")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90e')
    def test_list_group_roles_on_project(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.list_group_roles_on_project(
            self.project['id'],
            self.group['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90f')
    def test_create_user_role_on_domain(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.create_user_role_on_domain(
            self.domain['id'],
            self.user['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_user_on_domain,
                        self.domain['id'],
                        self.user['id'],
                        self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:revoke_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d910')
    def test_delete_role_from_user_on_domain(self):
        self.roles_client.create_user_role_on_domain(
            self.domain['id'],
            self.user['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_user_on_domain,
                        self.domain['id'],
                        self.user['id'],
                        self.role['id'])

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.delete_role_from_user_on_domain(
            self.domain['id'],
            self.user['id'],
            self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_grants")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d911')
    def test_list_user_roles_on_domain(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.list_user_roles_on_domain(
            self.domain['id'],
            self.user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d912')
    def test_create_group_role_on_domain(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.create_group_role_on_domain(
            self.domain['id'],
            self.group['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_domain,
                        self.domain['id'],
                        self.group['id'],
                        self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:revoke_grant")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d913')
    def test_delete_role_from_group_on_domain(self):
        self.roles_client.create_group_role_on_domain(
            self.domain['id'],
            self.group['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_domain,
                        self.domain['id'],
                        self.group['id'],
                        self.role['id'])

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.delete_role_from_group_on_domain(
            self.domain['id'],
            self.group['id'],
            self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_grants")
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d914')
    def test_list_group_roles_on_domain(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.roles_client.list_group_roles_on_domain(
            self.domain['id'],
            self.group['id'])
