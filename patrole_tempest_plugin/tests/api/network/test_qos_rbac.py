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


class QosExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(QosExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('qos', 'network'):
            msg = "qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(QosExtRbacTest, cls).resource_setup()
        cls.network = cls.create_network()

    def create_policy(self, name=None):
        name = name or data_utils.rand_name(self.__class__.__name__)
        policy = self.ntp_client.create_qos_policy(name)['policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.ntp_client.delete_qos_policy, policy['id'])
        return policy

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_policy"],
                                 expected_error_codes=[403])
    @decorators.idempotent_id('2ade2e48-7f82-4650-a69c-933d8d594636')
    def test_create_policy(self):

        """Create Policy Test

        RBAC test for the neutron create_policy policy
        """
        with self.rbac_utils.override_role(self):
            self.create_policy()

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy"],
                                 expected_error_codes=[404])
    @decorators.idempotent_id('d004a8de-b226-4eb4-9fdc-8202a7f64c56')
    def test_get_policy(self):

        """Show Policy Test

        RBAC test for the neutron get_policy policy
        """
        policy = self.create_policy()
        with self.rbac_utils.override_role(self):
            self.ntp_client.show_qos_policy(policy['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy", "update_policy"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('fb74d56f-1dfc-490b-a9e1-454af583eefb')
    def test_update_policy(self):

        """Update Policy Test

        RBAC test for the neutron update_policy policy
        """
        policy = self.create_policy()
        with self.rbac_utils.override_role(self):
            self.ntp_client.update_qos_policy(policy['id'],
                                              description='updated')

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_policy", "delete_policy"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('ef4c23a6-4095-47a6-958e-1df585f7d8db')
    def test_delete_policy(self):

        """Delete Policy Test

        RBAC test for the neutron delete_policy policy
        """
        policy = self.create_policy()
        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_qos_policy(policy['id'])
