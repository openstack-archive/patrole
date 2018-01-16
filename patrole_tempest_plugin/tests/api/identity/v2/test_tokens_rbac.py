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


class IdentityTokenV2RbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    def _create_token(self):

        user_name = self.client.auth_provider.credentials.username
        tenant_name = self.client.auth_provider.credentials.tenant_name
        password = self.client.auth_provider.credentials.password
        token_id = self.setup_test_token(user_name, password,
                                         tenant_name)
        return token_id

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:validate_token")
    @decorators.idempotent_id('71471202-4c4e-4a3d-9d41-57eb621bf3bb')
    def test_validate_token(self):

        """Validate token (get-token)

        RBAC test for Identity v2 get token validation
        """
        token_id = self._create_token()

        with self.rbac_utils.override_role(self):
            self.client.show_token(token_id)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:revoke_token")
    @decorators.idempotent_id('77338f66-0713-4f20-b11c-b0d750618276')
    def test_revoke_token(self):

        """Revoke token (delete-token)

        RBAC test for Identity v2 delete token
        """
        token_id = self._create_token()

        with self.rbac_utils.override_role(self):
            self.client.delete_token(token_id)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:validate_token_head")
    @decorators.idempotent_id('71471202-4c4e-4a3d-9d41-57eb621bf3ba')
    def test_check_token_existence(self):

        """Validate Token head

        RBAC test for Identity v2 token head validation
        """
        token_id = self._create_token()
        with self.rbac_utils.override_role(self):
            self.client.check_token_existence(token_id)
