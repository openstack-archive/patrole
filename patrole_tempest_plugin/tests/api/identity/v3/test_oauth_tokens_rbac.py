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

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base

CONF = config.CONF


class IdentityOAuthTokensV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def resource_setup(cls):
        super(IdentityOAuthTokensV3RbacTest, cls).resource_setup()
        # Authorize token on admin role since primary user has admin
        # credentials before switching roles. Populate role_ids with admin
        # role id.
        cls.role_ids = [cls.get_role_by_name(CONF.identity.admin_role)['id']]
        cls.project_id = cls.auth_provider.credentials.project_id
        cls.user_id = cls.auth_provider.credentials.user_id

    def _create_consumer(self):
        description = data_utils.rand_name(
            self.__class__.__name__ + '-Consumer')
        consumer = self.consumers_client.create_consumer(
            description)['consumer']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.consumers_client.delete_consumer,
                        consumer['id'])
        return consumer

    def _create_consumer_and_request_token(self):
        # Create consumer
        consumer = self._create_consumer()

        # Create request token
        request_token = self.oauth_token_client.create_request_token(
            consumer['id'], consumer['secret'], self.project_id)

        return consumer, request_token

    def _create_access_token(self):
        consumer, request_token = self._create_consumer_and_request_token()

        # Authorize request token
        resp = self.oauth_token_client.authorize_request_token(
            request_token['oauth_token'], self.role_ids)['token']
        auth_verifier = resp['oauth_verifier']

        # Create access token
        body = self.oauth_token_client.create_access_token(
            consumer['id'],
            consumer['secret'],
            request_token['oauth_token'],
            request_token['oauth_token_secret'],
            auth_verifier)
        access_key = body['oauth_token']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.oauth_token_client.revoke_access_token,
                        self.user_id, access_key)

        return access_key

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:authorize_request_token")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d976')
    def test_authorize_request_token(self):
        _, request_token = self._create_consumer_and_request_token()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.oauth_token_client.authorize_request_token(
            request_token['oauth_token'],
            self.role_ids)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_access_token")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d977')
    def test_get_access_token(self):
        access_token = self._create_access_token()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.oauth_token_client.get_access_token(self.user_id,
                                                 access_token)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_access_token_role")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d980')
    def test_get_access_token_role(self):
        access_token = self._create_access_token()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.oauth_token_client.get_access_token_role(
            self.user_id, access_token, self.role_ids[0])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_access_tokens")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d979')
    def test_list_access_tokens(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.oauth_token_client.list_access_tokens(self.user_id)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_access_token_roles")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d978')
    def test_list_access_token_roles(self):
        access_token = self._create_access_token()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.oauth_token_client.list_access_token_roles(
            self.user_id, access_token)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_access_token")
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d981')
    def test_revoke_access_token(self):
        access_token = self._create_access_token()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.oauth_token_client.revoke_access_token(
            self.user_id, access_token)
