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


class TrunksExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(TrunksExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('trunk', 'network'):
            msg = "trunk extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TrunksExtRbacTest, cls).resource_setup()
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


class TrunksSubportsExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(TrunksSubportsExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('trunk', 'network'):
            msg = "trunk extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TrunksSubportsExtRbacTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.port_id = cls.create_port(cls.network)["id"]
        cls.trunk_id = cls.ntp_client.create_trunk(
            cls.port_id, [])['trunk']['id']

        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.ntp_client.delete_trunk, cls.trunk_id)

    def create_subports(self, trunk_id, port_id):
        subports = [{'port_id': port_id,
                     'segmentation_type': 'vlan',
                     'segmentation_id': 4000}]
        sub = self.ntp_client.add_subports(trunk_id, subports)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.remove_subports,
            trunk_id, subports)
        return sub["sub_ports"]

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08133')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_trunk",
                                        "get_subports"],
                                 expected_error_codes=[404, 403])
    def test_get_subports(self):
        """Get subports.

        RBAC test for the neutron "get_subports" policy.

        Error 403 expected due to implementation of subports as a part of
        trunk object.
        """
        network = self.create_network()
        port = self.create_port(network)

        self.create_subports(self.trunk_id, port["id"])

        with self.rbac_utils.override_role(self):
            self.ntp_client.get_subports(self.trunk_id)

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08134')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_trunk",
                                        "add_subports"],
                                 expected_error_codes=[404, 403])
    def test_add_subports(self):
        """Add subports.

        RBAC test for the neutron "add_subports" policy

        Error 403 expected due to implementation of subports as a part of
        trunk object.
        """
        network = self.create_network()
        port = self.create_port(network)

        subports = [{'port_id': port["id"],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 4000}]
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.remove_subports,
            self.trunk_id, subports)

        with self.rbac_utils.override_role(self):
            self.ntp_client.add_subports(self.trunk_id, subports)

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08135')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_trunk",
                                        "remove_subports"],
                                 expected_error_codes=[404, 403])
    def test_remove_subports(self):
        """Remove subports.

        RBAC test for the neutron "remove_subports" policy

        Error 403 expected due to implementation of subports as a part of
        trunk object.
        """
        network = self.create_network()
        port = self.create_port(network)

        subports = self.create_subports(self.trunk_id, port["id"])

        with self.rbac_utils.override_role(self):
            self.ntp_client.remove_subports(self.trunk_id, subports)
