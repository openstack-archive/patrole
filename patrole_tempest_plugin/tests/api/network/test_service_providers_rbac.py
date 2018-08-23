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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class ServiceProvidersRbacTest(base.BaseNetworkRbacTest):

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_service_provider"])
    @decorators.idempotent_id('15f573b7-474a-4b37-8629-7fac86553ce5')
    def test_list_service_providers(self):
        with self.rbac_utils.override_role(self):
            self.service_providers_client.list_service_providers()
