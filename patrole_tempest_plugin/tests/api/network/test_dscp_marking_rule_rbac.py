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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class DscpMarkingRuleExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(DscpMarkingRuleExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('qos', 'network'):
            msg = "qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(DscpMarkingRuleExtRbacTest, cls).resource_setup()
        name = data_utils.rand_name(cls.__class__.__name__ + '-qos')
        cls.policy_id = cls.ntp_client.create_qos_policy(
            name=name)["policy"]["id"]
        cls.addClassResourceCleanup(
            cls.ntp_client.delete_qos_policy, cls.policy_id)

    def create_policy_dscp_marking_rule(cls):
        rule = cls.ntp_client.create_dscp_marking_rule(cls.policy_id, 10)
        rule_id = rule['dscp_marking_rule']['id']
        cls.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.ntp_client.delete_dscp_marking_rule, cls.policy_id, rule_id)
        return rule_id

    @decorators.idempotent_id('2717AB75-E4CF-4CA4-AF04-5BEC0C808AA5')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_policy_dscp_marking_rule"])
    def test_create_policy_dscp_marking_rule(self):
        """Create policy_dscp_marking_rule.

        RBAC test for the neutron "create_policy_dscp_marking_rule" policy
        """

        with self.rbac_utils.override_role(self):
            self.create_policy_dscp_marking_rule()

    @decorators.idempotent_id('3D68F50E-B948-4B25-8A72-F6F4890BBC6F')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_dscp_marking_rule"],
                                 expected_error_codes=[404])
    def test_show_policy_dscp_marking_rule(self):
        """Show policy_dscp_marking_rule.

        RBAC test for the neutron "get_policy_dscp_marking_rule" policy
        """
        rule_id = self.create_policy_dscp_marking_rule()

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_dscp_marking_rule(self.policy_id, rule_id)

    @decorators.idempotent_id('33830794-8731-45C3-BC97-17718555DD7C')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_dscp_marking_rule",
                                        "update_policy_dscp_marking_rule"],
                                 expected_error_codes=[404, 403])
    def test_update_policy_dscp_marking_rule(self):
        """Update policy_dscp_marking_rule.

        RBAC test for the neutron "update_policy_dscp_marking_rule" policy
        """
        rule_id = self.create_policy_dscp_marking_rule()

        with self.rbac_utils.override_role(self):
            self.ntp_client.update_dscp_marking_rule(
                self.policy_id, rule_id, dscp_mark=16)

    @decorators.idempotent_id('7BF564DD-3648-4D12-8A8B-6D5E576D1843')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_dscp_marking_rule",
                                        "delete_policy_dscp_marking_rule"],
                                 expected_error_codes=[404, 403])
    def test_delete_policy_dscp_marking_rule(self):
        """Delete policy_dscp_marking_rule.

        RBAC test for the neutron "delete_policy_dscp_marking_rule" policy
        """
        rule_id = self.create_policy_dscp_marking_rule()

        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_dscp_marking_rule(self.policy_id, rule_id)

    @decorators.idempotent_id('c012fd4f-3a3e-4af4-9075-dd3e170daecd')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_dscp_marking_rule"])
    def test_list_policy_dscp_marking_rules(self):
        """List policy_dscp_marking_rules.

        RBAC test for the neutron ``list_dscp_marking_rules`` function and
        the ``get_policy_dscp_marking_rule`` policy
        """
        admin_resource_id = self.create_policy_dscp_marking_rule()
        with (self.rbac_utils.override_role_and_validate_list(
                self, admin_resource_id=admin_resource_id)) as ctx:
            ctx.resources = self.ntp_client.list_dscp_marking_rules(
                policy_id=self.policy_id)["dscp_marking_rules"]
