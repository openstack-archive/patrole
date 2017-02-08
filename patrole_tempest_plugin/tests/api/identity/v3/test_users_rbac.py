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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base

CONF = config.CONF


class IdentityUserV3AdminRbacTest(
        rbac_base.BaseIdentityV3RbacAdminTest):

    def tearDown(self):
        """Reverts user back to admin for cleanup."""
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentityUserV3AdminRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d904')
    def test_create_user(self):
        """Creates a user.

        RBAC test for Keystone: identity:create_user
        """
        user_name = data_utils.rand_name('test_create_user')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.create_user(name=user_name)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d905')
    def test_update_user(self):
        """Updates a user.

        RBAC test for Keystone: identity:update_user
        """
        user_name = data_utils.rand_name('test_update_user')
        user = self._create_test_user(name=user_name, password=None)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.update_user(user['id'],
                                                name=user_name,
                                                email="changedUser@xyz.com")

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d906')
    def test_delete_user(self):
        """Get the list of users.

        RBAC test for Keystone: identity:delete_user
        """
        user_name = data_utils.rand_name('test_delete_user')
        user = self._create_test_user(name=user_name, password=None)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.delete_user(user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_users")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d907')
    def test_list_users(self):
        """Get the list of users.

        RBAC test for Keystone: identity:list_users
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.list_users()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d908')
    def test_show_user(self):
        """Get one user.

        RBAC test for Keystone: identity:get_user
        """
        user_name = data_utils.rand_name('test_get_user')
        user = self._create_test_user(name=user_name, password=None)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.show_user(user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:change_password")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d90a')
    def test_change_password(self):
        """Update a user password

        RBAC test for Keystone: identity:change_password
        """
        user_name = data_utils.rand_name('test_change_password')
        user = self._create_test_user(name=user_name, password='nova')

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client \
            .update_user_password(user['id'],
                                  original_password='nova',
                                  password='neutron')

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_groups_for_user")
    @decorators.idempotent_id('bd5946d4-46d2-423d-a800-a3e7aabc18b3')
    def test_list_group_user(self):
        """Lists groups which a user belongs to.

        RBAC test for Keystone: identity:list_groups_for_user
        """
        user_name = data_utils.rand_name('User')
        user = self._create_test_user(name=user_name, password=None)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.list_user_groups(user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_user_projects")
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d909')
    def test_list_user_projects(self):
        """List User's Projects.

        RBAC test for Keystone: identity:list_user_projects
        """
        user = self.setup_test_user()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.non_admin_users_client.list_user_projects(user['id'])
