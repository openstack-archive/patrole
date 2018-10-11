# Copyright 2018 AT&T Corporation.
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
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class RbacPoliciesExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def resource_setup(cls):
        super(RbacPoliciesExtRbacTest, cls).resource_setup()
        cls.tenant_id = cls.os_primary.credentials.tenant_id
        cls.network_id = cls.create_network()['id']

    def create_rbac_policy(self, tenant_id, network_id):
        policy = self.ntp_client.create_rbac_policy(
            target_tenant=tenant_id,
            object_type="network",
            object_id=network_id,
            action="access_as_shared"
        )
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_rbac_policy, policy["rbac_policy"]["id"])

        return policy["rbac_policy"]["id"]

    @decorators.idempotent_id('effd9545-99ad-4c3c-92dd-ea422602c868')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_rbac_policy",
                                        "create_rbac_policy:target_tenant"])
    def test_create_rbac_policy(self):
        """Create RBAC policy.

        RBAC test for the neutron "create_rbac_policy" policy

        We can't validate "create_rbac_policy:target_tenant" for all cases
        since if "restrict_wildcard" rule is modified then Patrole won't be
        able to determine the correct result since that requires relying on
        Neutron's custom FieldCheck oslo.policy rule.
        """

        with self.rbac_utils.override_role(self):
            self.create_rbac_policy(self.tenant_id, self.network_id)

    @decorators.idempotent_id('f5d836d8-3b64-412d-a283-ee29761017f3')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_rbac_policy",
                                        "update_rbac_policy",
                                        "update_rbac_policy:target_tenant"],
                                 expected_error_codes=[404, 403, 403])
    def test_update_rbac_policy(self):
        """Update RBAC policy.

        RBAC test for the neutron "update_rbac_policy" policy

        We can't validate "create_rbac_policy:target_tenant" for all cases
        since if "restrict_wildcard" rule is modified then Patrole won't be
        able to determine the correct result since that requires relying on
        Neutron's custom FieldCheck oslo.policy rule.
        """
        policy_id = self.create_rbac_policy(self.tenant_id, self.network_id)

        with self.rbac_utils.override_role(self):
            self.ntp_client.update_rbac_policy(
                policy_id, target_tenant=self.tenant_id)

    @decorators.idempotent_id('9308ab18-426c-41b7-bce5-11081f7dd259')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_rbac_policy"],
                                 expected_error_codes=[404])
    def test_show_rbac_policy(self):
        """Show RBAC policy.

        RBAC test for the neutron "get_rbac_policy" policy
        """
        policy_id = self.create_rbac_policy(self.tenant_id, self.network_id)

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_rbac_policy(policy_id)

    @decorators.idempotent_id('54aa9bce-efea-47fb-b0e4-12012f82f285')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_rbac_policy",
                                        "delete_rbac_policy"],
                                 expected_error_codes=[404, 403])
    def test_delete_rbac_policy(self):
        """Delete RBAC policy.

        RBAC test for the neutron "delete_rbac_policy" policy
        """
        policy_id = self.create_rbac_policy(self.tenant_id, self.network_id)

        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_rbac_policy(policy_id)

    @decorators.idempotent_id('5337d95a-2e75-47bb-a0ea-0a082be930bf')
    @rbac_rule_validation.action(service="neutron", rules=["get_rbac_policy"])
    def test_list_rbac_policies(self):
        """List RBAC policies.

        RBAC test for the neutron ``list_rbac_policies`` function and
        the ``get_rbac_policy`` policy
        """
        admin_resource_id = self.create_rbac_policy(self.tenant_id,
                                                    self.network_id)
        with (self.rbac_utils.override_role_and_validate_list(
                self, admin_resource_id=admin_resource_id)) as ctx:
            ctx.resources = self.ntp_client.list_rbac_policies(
                id=admin_resource_id)["rbac_policies"]
