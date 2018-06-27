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
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base

CONF = config.CONF


class MeteringLabelRulesRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(MeteringLabelRulesRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('metering', 'network'):
            msg = "metering extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(MeteringLabelRulesRbacTest, cls).setup_clients()
        cls.metering_labels_client = cls.os_primary.metering_labels_client
        cls.metering_label_rules_client = \
            cls.os_primary.metering_label_rules_client

    @classmethod
    def resource_setup(cls):
        super(MeteringLabelRulesRbacTest, cls).resource_setup()
        body = cls.metering_labels_client.create_metering_label(
            name=data_utils.rand_name(cls.__name__))
        cls.label = body['metering_label']
        cls.addClassResourceCleanup(
            cls.metering_labels_client.delete_metering_label, cls.label['id'])

    def _create_metering_label_rule(self, label):
        body = self.metering_label_rules_client.create_metering_label_rule(
            metering_label_id=label['id'],
            remote_ip_prefix=CONF.network.project_network_cidr,
            direction="ingress")
        label_rule = body['metering_label_rule']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.metering_label_rules_client.delete_metering_label_rule,
            label_rule['id'])
        return label_rule

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_metering_label_rule")
    @decorators.idempotent_id('81e81776-9d41-4d5e-b5c4-59d5c54a31ad')
    def test_create_metering_label_rule(self):
        """Create metering label rule.

        RBAC test for the neutron create_metering_label_rule policy
        """
        with self.rbac_utils.override_role(self):
            self._create_metering_label_rule(self.label)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_metering_label_rule",
                                 expected_error_code=404)
    @decorators.idempotent_id('e21b40c3-d44d-412f-84ea-836ca8603bcb')
    def test_show_metering_label_rule(self):
        """Show metering label rule.

        RBAC test for the neutron get_metering_label_rule policy
        """
        label_rule = self._create_metering_label_rule(self.label)
        with self.rbac_utils.override_role(self):
            self.metering_label_rules_client.show_metering_label_rule(
                label_rule['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_metering_label_rule",
                                        "delete_metering_label_rule"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('e3adc88c-05c0-43a7-8e32-63947ae4890e')
    def test_delete_metering_label_rule(self):
        """Delete metering label rule.

        RBAC test for the neutron delete_metering_label_rule policy
        """
        label_rule = self._create_metering_label_rule(self.label)
        with self.rbac_utils.override_role(self):
            self.metering_label_rules_client.delete_metering_label_rule(
                label_rule['id'])
