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
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityUserV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def resource_setup(cls):
        super(IdentityUserV3RbacTest, cls).resource_setup()
        cls.default_user_id = cls.os_primary.credentials.user_id

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_user"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d904')
    def test_create_user(self):
        with self.rbac_utils.override_role(self):
            self.setup_test_user()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:update_user"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d905')
    def test_update_user(self):
        user = self.setup_test_user()
        new_email = data_utils.rand_name(
            self.__class__.__name__ + '-user_email')

        with self.rbac_utils.override_role(self):
            self.users_client.update_user(user['id'],
                                          name=user['name'],
                                          email=new_email)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:delete_user"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d906')
    def test_delete_user(self):
        user = self.setup_test_user()

        with self.rbac_utils.override_role(self):
            self.users_client.delete_user(user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_users"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d907')
    def test_list_users(self):
        with self.rbac_utils.override_role(self):
            self.users_client.list_users()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:get_user"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d908')
    def test_show_own_user(self):
        with self.rbac_utils.override_role(self):
            self.users_client.show_user(self.default_user_id)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_groups_for_user"])
    @decorators.idempotent_id('bd5946d4-46d2-423d-a800-a3e7aabc18b3')
    def test_list_own_user_group(self):
        with self.rbac_utils.override_role(self):
            self.users_client.list_user_groups(self.default_user_id)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_user_projects"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1564-080044d0d909')
    def test_list_own_user_projects(self):
        with self.rbac_utils.override_role(self):
            self.users_client.list_user_projects(self.default_user_id)
