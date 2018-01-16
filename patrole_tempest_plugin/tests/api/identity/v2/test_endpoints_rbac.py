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
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityEndpointsV2AdminRbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd124')
    def test_create_endpoint(self):

        """Create Endpoint Test

        RBAC test for Identity v2 create_endpoint
        """

        with self.rbac_utils.override_role(self):
            self.setup_test_endpoint()

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd125')
    def test_delete_endpoint(self):

        """Delete Endpoint Test

        RBAC test for Identity v2 delete_endpoint
        """

        endpoint = self.setup_test_endpoint()
        with self.rbac_utils.override_role(self):
            self.endpoints_client.delete_endpoint(endpoint['id'])

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd126')
    def test_list_endpoints(self):

        """List Endpoints Test

        RBAC test for Identity v2 list_endpoint
        """

        with self.rbac_utils.override_role(self):
            self.endpoints_client.list_endpoints()
