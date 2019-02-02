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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityTokenV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def resource_setup(cls):
        super(IdentityTokenV3RbacTest, cls).resource_setup()
        cls.user_id = cls.os_primary.auth_provider.credentials.user_id
        cls.password = cls.os_primary.auth_provider.credentials.password

    @decorators.idempotent_id('201e2fe5-2023-4bce-9189-78b51520a91e')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:validate_token"],
        extra_target_data={
            "target.token.user_id":
            "os_primary.auth_provider.credentials.user_id"
        })
    def test_show_token(self):
        token_id = self.setup_test_token(self.user_id, self.password)
        with self.override_role():
            self.identity_client.show_token(token_id)

    @decorators.idempotent_id('42a299db-fe0a-4ea0-9824-0bfd13155886')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:revoke_token"],
        extra_target_data={
            "target.token.user_id":
            "os_primary.auth_provider.credentials.user_id"
        })
    def test_delete_token(self):
        token_id = self.setup_test_token(self.user_id, self.password)
        with self.override_role():
            self.identity_client.delete_token(token_id)

    @decorators.idempotent_id('3554d218-8cd6-4730-a1b2-0e22f9b78f45')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:check_token"],
        extra_target_data={
            "target.token.user_id":
            "os_primary.auth_provider.credentials.user_id"
        })
    def test_check_token_exsitence(self):
        token_id = self.setup_test_token(self.user_id, self.password)
        with self.override_role():
            self.identity_client.check_token_existence(token_id)
