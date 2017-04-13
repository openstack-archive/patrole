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
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base


class IdentityPoliciesV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_policy")
    @decorators.idempotent_id('de2f7ecb-fbf0-41f3-abf4-b97b5e082fd5')
    def test_create_policy(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.setup_test_policy()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_policy")
    @decorators.idempotent_id('9cfed3c6-0b27-4d15-be67-e06e0cfb01b9')
    def test_update_policy(self):
        policy = self.setup_test_policy()
        updated_policy_type = data_utils.rand_name('policy_type')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.policies_client.update_policy(policy['id'],
                                           type=updated_policy_type)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_policy")
    @decorators.idempotent_id('dcd93f75-1e1b-4fbe-bee0-9c4c7b201735')
    def test_delete_policy(self):
        policy = self.setup_test_policy()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.policies_client.delete_policy(policy['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_policy")
    @decorators.idempotent_id('d7e415c2-945a-4504-9571-0e2d0dd8594b')
    def test_show_policy(self):
        policy = self.setup_test_policy()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.policies_client.show_policy(policy['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_policies")
    @decorators.idempotent_id('35a56161-4054-4237-8a78-7ce805dce202')
    def test_list_policies(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.policies_client.list_policies()['policies']
