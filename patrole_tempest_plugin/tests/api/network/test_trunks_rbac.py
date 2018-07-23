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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class TrunksPluginRbacTest(base.BaseNetworkPluginRbacTest):

    @classmethod
    def skip_checks(cls):
        super(TrunksPluginRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('trunk', 'network'):
            msg = "trunk extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TrunksPluginRbacTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.port_id = cls.create_port(cls.network)["id"]

    def create_trunk(self, port_id):
        trunk = self.ntp_client.create_trunk(port_id, [])
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_trunk, trunk["trunk"]['id'])

        return trunk

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08130')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_trunk"])
    def test_create_trunk(self):
        """Create trunk.

        RBAC test for the neutron "create_trunk" policy
        """
        with self.rbac_utils.override_role(self):
            self.create_trunk(self.port_id)

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08131')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_trunk"],
                                 expected_error_codes=[404])
    def test_show_trunk(self):
        """Show trunk.

        RBAC test for the neutron "get_trunk" policy
        """
        trunk = self.create_trunk(self.port_id)

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_trunk(trunk['trunk']['id'])

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08132')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_trunk",
                                        "delete_trunk"],
                                 expected_error_codes=[404, 403])
    def test_delete_trunk(self):
        """Delete trunk.

        RBAC test for the neutron "delete_trunk" policy
        """
        trunk = self.create_trunk(self.port_id)

        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_trunk(trunk['trunk']['id'])
