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
from patrole_tempest_plugin.tests.api.identity.v2 import rbac_base


class IdentityUserV2AdminRbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d904')
    def test_create_user(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_user()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d905')
    def test_update_user(self):
        user = self._create_user()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.users_client.update_user(user['id'], email="changedUser@xyz.com")

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:set_user_enabled")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d9a1')
    def test_update_user_enabled(self):
        user = self._create_user()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.users_client.update_user_enabled(user['id'], enabled=True)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d906')
    def test_delete_user(self):
        user = self._create_user()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.users_client.delete_user(user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_users")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d907')
    def test_list_users(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.users_client.list_users()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_user")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d908')
    def test_show_user(self):
        user = self._create_user()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.users_client.show_user(user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:change_password")
    @decorators.idempotent_id('0f148510-63bf-11e6-1342-080044d0d909')
    def test_update_user_password(self):
        user = self._create_user()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.users_client.update_user_password(
            user['id'], password=data_utils.rand_password())
