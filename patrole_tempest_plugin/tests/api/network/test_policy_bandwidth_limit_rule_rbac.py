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


class PolicyBandwidthLimitRulePluginRbacTest(base.BaseNetworkPluginRbacTest):

    @classmethod
    def skip_checks(cls):
        super(PolicyBandwidthLimitRulePluginRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('qos', 'network'):
            msg = "qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(PolicyBandwidthLimitRulePluginRbacTest, cls).resource_setup()
        name = data_utils.rand_name(cls.__class__.__name__ + '-qos-policy')
        cls.policy_id = cls.ntp_client.create_qos_policy(
            name=name)["policy"]["id"]
        cls.addClassResourceCleanup(cls.ntp_client.delete_qos_policy,
                                    cls.policy_id)

    def _create_bandwidth_limit_rule(self):
        rule = self.ntp_client.create_bandwidth_limit_rule(
            self.policy_id, max_kbps=1000, max_burst_kbps=1000,
            direction="egress")
        rule_id = rule['bandwidth_limit_rule']['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.ntp_client.delete_bandwidth_limit_rule,
                        self.policy_id, rule_id)
        return rule_id

    @decorators.idempotent_id('E0FDCB39-E16D-4AF5-9165-3FEFD116E69D')
    @rbac_rule_validation.action(
        service="neutron", rules=["create_policy_bandwidth_limit_rule"])
    def test_create_policy_bandwidth_limit_rule(self):
        """Create bandwidth_limit_rule.

        RBAC test for the neutron "create_policy_bandwidth_limit_rule" policy
        """

        with self.rbac_utils.override_role(self):
            self._create_bandwidth_limit_rule()

    @decorators.idempotent_id('A092BD50-364F-4F55-B81A-37DAD6E77B95')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_bandwidth_limit_rule"],
                                 expected_error_codes=[404])
    def test_show_policy_bandwidth_limit_rule(self):
        """Show bandwidth_limit_rule.

        RBAC test for the neutron "get_policy_bandwidth_limit_rule" policy
        """
        rule_id = self._create_bandwidth_limit_rule()

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_bandwidth_limit_rule(self.policy_id, rule_id)

    @decorators.idempotent_id('CAA27599-082B-44B9-AF09-8C9B8E777ED7')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_bandwidth_limit_rule",
                                        "update_policy_bandwidth_limit_rule"],
                                 expected_error_codes=[404, 403])
    def test_update_policy_bandwidth_limit_rule(self):
        """Update bandwidth_limit_rule.

        RBAC test for the neutron "update_policy_bandwidth_limit_rule" policy
        """
        rule_id = self._create_bandwidth_limit_rule()

        with self.rbac_utils.override_role(self):
            self.ntp_client.update_bandwidth_limit_rule(
                self.policy_id, rule_id, max_kbps=2000)

    @decorators.idempotent_id('BF6D9ED7-4B04-423D-857D-455DB0705852')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy_bandwidth_limit_rule",
                                        "delete_policy_bandwidth_limit_rule"],
                                 expected_error_codes=[404, 403])
    def test_delete_policy_bandwidth_limit_rule(self):
        """Delete bandwidth_limit_rule.

        RBAC test for the neutron "delete_policy_bandwidth_limit_rule" policy
        """
        rule_id = self._create_bandwidth_limit_rule()

        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_bandwidth_limit_rule(self.policy_id,
                                                        rule_id)
