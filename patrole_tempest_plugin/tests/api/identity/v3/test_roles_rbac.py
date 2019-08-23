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
from patrole_tempest_plugin.tests.api.identity import rbac_base

CONF = config.CONF


class IdentityRolesV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def resource_setup(cls):
        super(IdentityRolesV3RbacTest, cls).resource_setup()
        cls.domain = cls.setup_test_domain()
        cls.project = cls.setup_test_project()
        cls.group = cls.setup_test_group()
        cls.role = cls.setup_test_role()
        cls.implies_role = cls.setup_test_role()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_role"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d904')
    def test_create_role(self):
        with self.override_role():
            self.setup_test_role()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:update_role"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d905')
    def test_update_role(self):
        new_role_name = data_utils.rand_name(
            self.__class__.__name__ + '-test_update_role')

        with self.override_role():
            self.roles_client.update_role(self.role['id'],
                                          name=new_role_name)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:delete_role"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d906')
    def test_delete_role(self):
        role = self.setup_test_role()

        with self.override_role():
            self.roles_client.delete_role(role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:get_role"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d907')
    def test_show_role(self):
        with self.override_role():
            self.roles_client.show_role(self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_roles"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d908')
    def test_list_roles(self):
        with self.override_role():
            self.roles_client.list_roles()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_grant"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90c')
    def test_create_group_role_on_project(self):
        with self.override_role():
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
                                 rules=["identity:create_grant"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d912')
    def test_create_group_role_on_domain(self):
        with self.override_role():
            self.roles_client.create_group_role_on_domain(
                self.domain['id'],
                self.group['id'],
                self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_domain,
                        self.domain['id'],
                        self.group['id'],
                        self.role['id'])

    @decorators.idempotent_id('8738d3d2-8c84-4423-b36c-7c59eaa08b73')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:check_grant"])
    def test_check_role_from_group_on_project_existence(self):
        self.roles_client.create_group_role_on_project(
            self.project['id'],
            self.group['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_project,
                        self.project['id'],
                        self.group['id'],
                        self.role['id'])

        with self.override_role():
            self.roles_client.check_role_from_group_on_project_existence(
                self.project['id'],
                self.group['id'],
                self.role['id'])

    @decorators.idempotent_id('e7d73bd0-cf5e-4c0c-9c93-cf53e23232d6')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:check_grant"])
    def test_check_role_from_group_on_domain_existence(self):
        self.roles_client.create_group_role_on_domain(
            self.domain['id'],
            self.group['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_group_on_domain,
                        self.domain['id'],
                        self.group['id'],
                        self.role['id'])

        with self.override_role():
            self.roles_client.check_role_from_group_on_domain_existence(
                self.domain['id'],
                self.group['id'],
                self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:revoke_grant"])
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

        with self.override_role():
            self.roles_client.delete_role_from_group_on_project(
                self.project['id'],
                self.group['id'],
                self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:revoke_grant"])
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

        with self.override_role():
            self.roles_client.delete_role_from_group_on_domain(
                self.domain['id'],
                self.group['id'],
                self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_grants"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90e')
    def test_list_group_roles_on_project(self):
        with self.override_role():
            self.roles_client.list_group_roles_on_project(
                self.project['id'],
                self.group['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_grants"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d914')
    def test_list_group_roles_on_domain(self):
        with self.override_role():
            self.roles_client.list_group_roles_on_domain(
                self.domain['id'],
                self.group['id'])

    @decorators.idempotent_id('2aef3eaa-8156-4962-a01d-c9bb0e499e15')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_implied_role"])
    def test_create_role_inference_rule(self):
        with self.override_role():
            self.roles_client.create_role_inference_rule(
                self.role['id'], self.implies_role['id'])
        self.addCleanup(self.roles_client.delete_role_inference_rule,
                        self.role['id'], self.implies_role['id'])

    @decorators.idempotent_id('83f997b2-55c4-4894-b1f2-e175b19d1fa5')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:get_implied_role"])
    def test_show_role_inference_rule(self):
        self.roles_client.create_role_inference_rule(
            self.role['id'], self.implies_role['id'])
        self.addCleanup(self.roles_client.delete_role_inference_rule,
                        self.role['id'], self.implies_role['id'])

        with self.override_role():
            self.roles_client.show_role_inference_rule(
                self.role['id'], self.implies_role['id'])

    @decorators.idempotent_id('f7bb39bf-0b06-468e-a8b0-60a4fb1f258d')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_implied_roles"])
    def test_list_role_inferences_rules(self):
        with self.override_role():
            self.roles_client.list_role_inferences_rules(self.role['id'])

    @decorators.idempotent_id('eca2d502-09bb-45cd-9773-bce2e7bcddd1')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:check_implied_role"])
    def test_check_role_inference_rule(self):
        self.roles_client.create_role_inference_rule(
            self.role['id'], self.implies_role['id'])
        self.addCleanup(self.roles_client.delete_role_inference_rule,
                        self.role['id'], self.implies_role['id'])

        with self.override_role():
            self.roles_client.check_role_inference_rule(
                self.role['id'], self.implies_role['id'])

    @decorators.idempotent_id('13a5db1e-dd4a-4ca1-81ec-d5452aaaf54b')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:delete_implied_role"])
    def test_delete_role_inference_rule(self):
        self.roles_client.create_role_inference_rule(
            self.role['id'], self.implies_role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_inference_rule,
                        self.role['id'], self.implies_role['id'])

        with self.override_role():
            self.roles_client.delete_role_inference_rule(
                self.role['id'], self.implies_role['id'])

    @decorators.idempotent_id('05869f2b-4dd4-425a-905e-eec9a6f06374')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_role_inference_rules"])
    def test_list_all_role_inference_rules(self):
        with self.override_role():
            self.roles_client.list_all_role_inference_rules()


class IdentityRolesUserCreateV3RbacTest(rbac_base.BaseIdentityV3RbacTest):
    """Tests identity roles v3 API endpoints that require user creation.
    This is in a separate class to better manage immutable user source feature
    flag.
    """

    @classmethod
    def skip_checks(cls):
        super(IdentityRolesUserCreateV3RbacTest, cls).skip_checks()
        if CONF.identity_feature_enabled.immutable_user_source:
            raise cls.skipException('Skipped because environment has an '
                                    'immutable user source and solely '
                                    'provides read-only access to users.')

    @classmethod
    def resource_setup(cls):
        super(IdentityRolesUserCreateV3RbacTest, cls).resource_setup()
        cls.domain = cls.setup_test_domain()
        cls.project = cls.setup_test_project()
        cls.group = cls.setup_test_group()
        cls.role = cls.setup_test_role()
        cls.implies_role = cls.setup_test_role()
        cls.user = cls.setup_test_user()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_grant"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d909')
    def test_create_user_role_on_project(self):
        with self.override_role():
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
                                 rules=["identity:create_grant"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90f')
    def test_create_user_role_on_domain(self):
        with self.override_role():
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
                                 rules=["identity:check_grant"])
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

        with self.override_role():
            self.roles_client.check_user_role_existence_on_project(
                self.project['id'],
                self.user['id'],
                self.role['id'])

    @decorators.idempotent_id('92f8e67d-85bf-407d-9814-edd5664abc47')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:check_grant"])
    def test_check_user_role_existence_on_domain(self):
        self.roles_client.create_user_role_on_domain(
            self.domain['id'],
            self.user['id'],
            self.role['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role_from_user_on_domain,
                        self.domain['id'],
                        self.user['id'],
                        self.role['id'])

        with self.override_role():
            self.roles_client.check_user_role_existence_on_domain(
                self.domain['id'],
                self.user['id'],
                self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:revoke_grant"])
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

        with self.override_role():
            self.roles_client.delete_role_from_user_on_project(
                self.project['id'],
                self.user['id'],
                self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:revoke_grant"])
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

        with self.override_role():
            self.roles_client.delete_role_from_user_on_domain(
                self.domain['id'],
                self.user['id'],
                self.role['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_grants"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d90b')
    def test_list_user_roles_on_project(self):
        with self.override_role():
            self.roles_client.list_user_roles_on_project(
                self.project['id'],
                self.user['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_grants"])
    @decorators.idempotent_id('0f148510-63bf-11e6-1395-080044d0d911')
    def test_list_user_roles_on_domain(self):
        with self.override_role():
            self.roles_client.list_user_roles_on_domain(
                self.domain['id'],
                self.user['id'])
