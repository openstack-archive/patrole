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

from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityPolicyAssociationRbacTest(
        rbac_base.BaseIdentityV3RbacTest):

    def setUp(self):
        super(IdentityPolicyAssociationRbacTest, self).setUp()
        self.policy_id = self.setup_test_policy()['id']
        self.service_id = self.setup_test_service()['id']
        self.endpoint_id = self.setup_test_endpoint()['id']
        self.region_id = self.setup_test_region()['id']

    def _update_policy_association_for_endpoint(self, policy_id, endpoint_id):
        self.policies_client.update_policy_association_for_endpoint(
            policy_id, endpoint_id)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.policies_client.delete_policy_association_for_endpoint,
            policy_id, endpoint_id)

    def _update_policy_association_for_service(self, policy_id, service_id):
        self.policies_client.update_policy_association_for_service(
            policy_id, service_id)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.policies_client.delete_policy_association_for_service,
            policy_id, service_id)

    def _update_policy_association_for_region_and_service(
            self, policy_id, service_id, region_id):
        self.policies_client.update_policy_association_for_region_and_service(
            policy_id, service_id, region_id)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.policies_client.
            delete_policy_association_for_region_and_service,
            policy_id, service_id, region_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:create_policy_association_for_endpoint"])
    @decorators.idempotent_id('1b3f4f62-4f4a-4d27-be27-9a113058597f')
    def test_update_policy_association_for_endpoint(self):
        with self.rbac_utils.override_role(self):
            self._update_policy_association_for_endpoint(
                self.policy_id, self.endpoint_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:check_policy_association_for_endpoint"])
    @decorators.idempotent_id('25ce8c89-e751-465c-8d35-52bacd774beb')
    def test_show_policy_association_for_endpoint(self):
        self._update_policy_association_for_endpoint(
            self.policy_id, self.endpoint_id)
        with self.rbac_utils.override_role(self):
            self.policies_client.show_policy_association_for_endpoint(
                self.policy_id, self.endpoint_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:delete_policy_association_for_endpoint"])
    @decorators.idempotent_id('95cad2d8-bcd0-4c4e-a8f7-cc80601e43a1')
    def test_delete_policy_association_for_endpoint(self):
        self._update_policy_association_for_endpoint(
            self.policy_id, self.endpoint_id)
        with self.rbac_utils.override_role(self):
            self.policies_client.delete_policy_association_for_endpoint(
                self.policy_id, self.endpoint_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:create_policy_association_for_service"])
    @decorators.idempotent_id('57fb80fe-6ce2-4995-b710-4692b3fc3cdc')
    def test_update_policy_association_for_service(self):
        with self.rbac_utils.override_role(self):
            self._update_policy_association_for_service(
                self.policy_id, self.service_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:check_policy_association_for_service"])
    @decorators.idempotent_id('5cbe285f-4888-4f98-978f-30210ff28b74')
    def test_show_policy_association_for_service(self):
        self._update_policy_association_for_service(
            self.policy_id, self.service_id)
        with self.rbac_utils.override_role(self):
            self.policies_client.show_policy_association_for_service(
                self.policy_id, self.service_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:delete_policy_association_for_service"])
    @decorators.idempotent_id('f754455c-02a4-4fb6-8c73-64ef453f955f')
    def test_delete_policy_association_for_service(self):
        self._update_policy_association_for_service(
            self.policy_id, self.service_id)
        with self.rbac_utils.override_role(self):
            self.policies_client.delete_policy_association_for_service(
                self.policy_id, self.service_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:create_policy_association_for_region_and_service"])
    @decorators.idempotent_id('54d2a93e-c84d-4079-8ea9-2fb227c262a1')
    def test_update_policy_association_for_region_and_service(self):
        with self.rbac_utils.override_role(self):
            self._update_policy_association_for_region_and_service(
                self.policy_id, self.service_id, self.region_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:check_policy_association_for_region_and_service"])
    @decorators.idempotent_id('0763b780-52c1-47bc-9316-1fe12a2ab0bc')
    def test_show_policy_association_for_region_and_service(self):
        self._update_policy_association_for_region_and_service(
            self.policy_id, self.service_id, self.region_id)
        with self.rbac_utils.override_role(self):
            self.policies_client\
                .show_policy_association_for_region_and_service(
                    self.policy_id, self.service_id, self.region_id)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:delete_policy_association_for_region_and_service"])
    @decorators.idempotent_id('9c956888-81d4-4a24-8203-bff7b8a7834c')
    def test_delete_policy_association_for_region_and_service(self):
        self._update_policy_association_for_region_and_service(
            self.policy_id, self.service_id, self.region_id)
        with self.rbac_utils.override_role(self):
            self.policies_client.\
                delete_policy_association_for_region_and_service(
                    self.policy_id, self.service_id, self.region_id)
