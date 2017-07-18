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
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base

CONF = config.CONF


class IdentityTrustV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    credentials = ['primary', 'admin', 'alt']

    @classmethod
    def skip_checks(cls):
        super(IdentityTrustV3RbacTest, cls).skip_checks()
        if not CONF.identity_feature_enabled.trust:
            raise cls.skipException(
                "%s skipped as trust feature isn't enabled" % cls.__name__)

    @classmethod
    def resource_setup(cls):
        super(IdentityTrustV3RbacTest, cls).resource_setup()
        # Use the primary user's credentials for the "trustor_user_id", since
        # user_id:%(trust.trustor_user_id)s will thereby evaluate to
        # "primary user's user_id:primary user's user_id" which evaluates to
        # true.
        cls.trustor_user_id = cls.auth_provider.credentials.user_id
        cls.trustor_project_id = cls.auth_provider.credentials.project_id
        cls.trustee_user_id = cls.setup_test_user()['id']

        # The "unauthorized_user_id" does not have permissions to create a
        # trust because the user_id in "user_id:%(trust.trustor_user_id)s" (the
        # policy rule for creating a trust) corresponds to the primary user_id
        # not the alt user_id.
        cls.unauthorized_user_id = cls.os_alt.auth_provider.credentials.user_id

        # A role is guaranteed to exist (namely the admin role), because
        # "trustor_user_id" and "trustor_project_id" are the primary tempest
        # user and project, respectively.
        cls.delegated_role_id = cls.roles_client.list_user_roles_on_project(
            cls.trustor_project_id, cls.trustor_user_id)['roles'][0]['id']

        cls.trust = cls.setup_test_trust(trustor_user_id=cls.trustor_user_id,
                                         trustee_user_id=cls.trustee_user_id,
                                         project_id=cls.trustor_project_id,
                                         roles=[{'id': cls.delegated_role_id}])

    @decorators.idempotent_id('7ab595a7-9b71-45fe-91d8-2793b0292f72')
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:create_trust",
        extra_target_data={
            "trust.trustor_user_id":
            "os_primary.auth_provider.credentials.user_id"
        })
    def test_create_trust(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.setup_test_trust(trustor_user_id=self.trustor_user_id,
                              trustee_user_id=self.trustee_user_id)

    @decorators.idempotent_id('bd72d22a-6e11-4840-bd93-17b382e7f0e0')
    @decorators.attr(type=['negative'])
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:create_trust",
        extra_target_data={
            "trust.trustor_user_id": "os_alt.auth_provider.credentials.user_id"
        })
    def test_create_trust_negative(self):
        # Explicit negative test for identity:create_trust policy action.
        # Assert expected exception is Forbidden and then reraise it.
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        e = self.assertRaises(lib_exc.Forbidden, self.setup_test_trust,
                              trustor_user_id=self.unauthorized_user_id,
                              trustee_user_id=self.trustee_user_id)
        raise e

    @decorators.idempotent_id('d9a6fd06-08f6-462c-a86c-ce009adf1230')
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:delete_trust")
    def test_delete_trust(self):
        trust = self.setup_test_trust(trustor_user_id=self.trustor_user_id,
                                      trustee_user_id=self.trustee_user_id)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.trusts_client.delete_trust(trust['id'])

    @decorators.idempotent_id('f2e32896-bf66-4f4e-89cf-e7fba0ef1f38')
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:list_trusts")
    def test_list_trusts(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.trusts_client.list_trusts(
            trustor_user_id=self.trustor_user_id)['trusts']

    @decorators.idempotent_id('3c9ff92f-a73e-4f9b-8865-e017f38c70f5')
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:list_roles_for_trust")
    def test_list_roles_for_trust(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.trusts_client.list_trust_roles(self.trust['id'])['roles']

    @decorators.idempotent_id('3bb4f97b-cecd-4c7d-ad10-b88ee6c5d573')
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:get_role_for_trust")
    def test_show_trust_role(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.trusts_client.show_trust_role(
            self.trust['id'], self.delegated_role_id)['role']
