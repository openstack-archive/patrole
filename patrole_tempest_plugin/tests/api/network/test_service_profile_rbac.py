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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class ServiceProfileExtRbacTest(base.BaseNetworkExtRbacTest):
    @decorators.idempotent_id('6ce76efa-7400-44c1-80ec-58f79b1d89ca')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_service_profile"])
    def test_create_service_profile(self):
        """Create service profile

        RBAC test for the neutron "create_service_profile" policy
        """
        with self.rbac_utils.override_role(self):
            self.create_service_profile()

    @decorators.idempotent_id('e4c473b7-3ae9-4a2e-8cac-848f7b01187d')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_service_profile"],
                                 expected_error_codes=[404])
    def test_show_service_profile(self):
        """Show service profile

        RBAC test for the neutron "get_service_profile" policy
        """
        profile_id = self.create_service_profile()
        with self.rbac_utils.override_role(self):
            self.ntp_client.show_service_profile(profile_id)

    @decorators.idempotent_id('a3dd719d-4cd3-40cc-b4f1-5642e2717adf')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_service_profile",
                                        "update_service_profile"],
                                 expected_error_codes=[404, 403])
    def test_update_service_profile(self):
        """Update service profile

        RBAC test for the neutron "update_service_profile" policy
        """
        profile_id = self.create_service_profile()
        with self.rbac_utils.override_role(self):
            self.ntp_client.update_service_profile(profile_id, enabled=False)

    @decorators.idempotent_id('926b60c2-04fe-4339-aa44-bf27121392e8')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_service_profile",
                                        "delete_service_profile"],
                                 expected_error_codes=[404, 403])
    def test_delete_service_profile(self):
        """Delete service profile

        RBAC test for the neutron "delete_service_profile" policy
        """
        profile_id = self.create_service_profile()
        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_service_profile(profile_id)
