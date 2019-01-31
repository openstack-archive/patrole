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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class NetworkIpAvailabilityExtRbacTest(base.BaseNetworkExtRbacTest):
    @classmethod
    def skip_checks(cls):
        super(NetworkIpAvailabilityExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('network-ip-availability',
                                          'network'):
            msg = "network-ip-availability extension not enabled."
            raise cls.skipException(msg)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network_ip_availability"],
                                 expected_error_codes=[404])
    @decorators.idempotent_id('93edc5ed-385f-4a8e-9b15-4370ec608253')
    def test_get_network_ip_availability(self):
        """Get network availability

        RBAC test for the neutron get_network_ip_availability policy
        """

        network_name = data_utils.rand_name(
            self.__class__.__name__ + '-Network')
        network = self.create_network(network_name=network_name)

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_network_ip_availability(network['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network_ip_availability"])
    @decorators.idempotent_id('d4ceb5f0-2342-4412-a617-4e1aaf7fcaf0')
    def test_get_network_ip_availabilities(self):
        """List network ip availabilities

        RBAC test for the neutron "get_network_ip_availability" policy
        for the "list_network_ip_availabilities" action.
        """
        admin_resources = (self.ntp_client.list_network_ip_availabilities()
                           ["network_ip_availabilities"])
        with self.rbac_utils.override_role_and_validate_list(
                self, admin_resources=admin_resources) as ctx:
            ctx.resources = (self.ntp_client.list_network_ip_availabilities()
                             ["network_ip_availabilities"])
