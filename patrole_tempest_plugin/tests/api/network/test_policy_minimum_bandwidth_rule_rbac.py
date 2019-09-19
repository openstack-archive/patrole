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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class PolicyMinimumBandwidthRuleExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(PolicyMinimumBandwidthRuleExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('qos', 'network'):
            msg = "qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(PolicyMinimumBandwidthRuleExtRbacTest, cls).resource_setup()
        name = data_utils.rand_name(cls.__name__ + '-qos')
        cls.policy_id = cls.ntp_client.create_qos_policy(
            name=name)["policy"]["id"]
        cls.addClassResourceCleanup(test_utils.call_and_ignore_notfound_exc,
                                    cls.ntp_client.delete_qos_policy,
                                    cls.policy_id)

    def create_minimum_bandwidth_rule(self):
        rule = self.ntp_client.create_minimum_bandwidth_rule(
            self.policy_id, direction="egress", min_kbps=1000)
        rule_id = rule['minimum_bandwidth_rule']['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.ntp_client.delete_minimum_bandwidth_rule,
                        self.policy_id, rule_id)
        return rule_id

    @decorators.idempotent_id('25B5EF3A-DF2A-4C80-A498-3BE14A321D97')
    @rbac_rule_validation.action(
        service="neutron", rules=["create_policy_minimum_bandwidth_rule"])
    def test_create_policy_minimum_bandwidth_rule(self):
        """Create policy_minimum_bandwidth_rule.

        RBAC test for the neutron "create_policy_minimum_bandwidth_rule" policy
        """

        with self.override_role():
            self.create_minimum_bandwidth_rule()

    @decorators.idempotent_id('01DD902C-47C5-45D2-9A0E-7AF05981DF21')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_minimum_bandwidth_rule"],
                                 expected_error_codes=[404])
    def test_show_policy_minimum_bandwidth_rule(self):
        """Show policy_minimum_bandwidth_rule.

        RBAC test for the neutron "get_policy_minimum_bandwidth_rule" policy
        """
        rule_id = self.create_minimum_bandwidth_rule()

        with self.override_role():
            self.ntp_client.show_minimum_bandwidth_rule(
                self.policy_id, rule_id)

    @decorators.idempotent_id('50AFE69B-455C-413A-BDC6-26B42DC8D55D')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["get_policy_minimum_bandwidth_rule",
               "update_policy_minimum_bandwidth_rule"],
        expected_error_codes=[404, 403])
    def test_update_policy_minimum_bandwidth_rule(self):
        """Update policy_minimum_bandwidth_rule.

        RBAC test for the neutron "update_policy_minimum_bandwidth_rule" policy
        """
        rule_id = self.create_minimum_bandwidth_rule()

        with self.override_role():
            self.ntp_client.update_minimum_bandwidth_rule(
                self.policy_id, rule_id, min_kbps=2000)

    @decorators.idempotent_id('2112E325-C3B2-4071-8A93-B218F275A83B')
    @rbac_rule_validation.action(
        service="neutron",
        rules=["get_policy_minimum_bandwidth_rule",
               "delete_policy_minimum_bandwidth_rule"],
        expected_error_codes=[404, 403])
    def test_delete_policy_minimum_bandwidth_rule(self):
        """Delete policy_minimum_bandwidth_rule.

        RBAC test for the neutron "delete_policy_minimum_bandwidth_rule" policy
        """
        rule_id = self.create_minimum_bandwidth_rule()

        with self.override_role():
            self.ntp_client.delete_minimum_bandwidth_rule(
                self.policy_id, rule_id)
