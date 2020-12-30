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
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin import rbac_utils
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityTokenV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def skip_checks(cls):
        super(IdentityTokenV3RbacTest, cls).skip_checks()
        # In case of admin, the positive testcase would be used, hence
        # skipping negative testcase.
        if rbac_utils.is_admin():
            raise cls.skipException(
                "Skipped as admin role doesn't require negative testing")

    def _setup_alt_token(self):
        return self.setup_test_token(
            self.os_alt.auth_provider.credentials.user_id,
            self.os_alt.auth_provider.credentials.password)

    @decorators.idempotent_id('c83c8f1a-79cb-4dc4-b55f-c7d2bfd98b1e')
    @decorators.attr(type=['negative'])
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:validate_token"],
        extra_target_data={
            "target.token.user_id":
            "os_alt.auth_provider.credentials.user_id"
        })
    def test_show_token_negative(self):
        # Explicit negative test for identity:validate_token policy action.
        # Assert expected exception is Forbidden and then reraise it.
        alt_token_id = self._setup_alt_token()
        with self.override_role():
            e = self.assertRaises(lib_exc.Forbidden,
                                  self.identity_client.show_token,
                                  alt_token_id)
            raise e

    @decorators.idempotent_id('2786a55d-a818-433a-af7a-41ebf72ab4da')
    @decorators.attr(type=['negative'])
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:revoke_token"],
        extra_target_data={
            "target.token.user_id":
            "os_alt.auth_provider.credentials.user_id"
        })
    def test_delete_token_negative(self):
        # Explicit negative test for identity:revoke_token policy action.
        # Assert expected exception is Forbidden and then reraise it.
        alt_token_id = self._setup_alt_token()
        with self.override_role():
            e = self.assertRaises(lib_exc.Forbidden,
                                  self.identity_client.delete_token,
                                  alt_token_id)
            raise e

    @decorators.idempotent_id('1ea02ac0-9a96-44bd-bdc3-4dae3c10cc2e')
    @decorators.attr(type=['negative'])
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:check_token"],
        extra_target_data={
            "target.token.user_id":
            "os_alt.auth_provider.credentials.user_id"
        })
    def test_check_token_existence_negative(self):
        # Explicit negative test for identity:check_token policy action.
        # Assert expected exception is Forbidden and then reraise it.
        alt_token_id = self._setup_alt_token()
        with self.override_role():
            e = self.assertRaises(lib_exc.Forbidden,
                                  self.identity_client.check_token_existence,
                                  alt_token_id)
            raise e
