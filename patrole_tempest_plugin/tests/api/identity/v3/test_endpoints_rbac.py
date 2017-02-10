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

from tempest.common.utils import data_utils
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base

CONF = config.CONF


class IdentityEndpointsV3AdminRbacTest(
        rbac_base.BaseIdentityV3RbacAdminTest):

    def _create_endpoint(self):
        """Creates a service and an endpoint for test."""
        interface = 'public'
        url = data_utils.rand_url()
        service = self._create_service()
        endpoint = self.endpoints_client \
                       .create_endpoint(service_id=service['id'],
                                        interface=interface,
                                        url=url)['endpoint']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.endpoints_client.delete_endpoint, endpoint['id'])
        return (service, endpoint)

    def tearDown(self):
        """Reverts user back to admin for cleanup."""
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentityEndpointsV3AdminRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_endpoint")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd127')
    def test_create_endpoint(self):
        """Create an endpoint.

        RBAC test for Keystone: identity:create_endpoint
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_endpoint()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_endpoint")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd128')
    def test_update_endpoint(self):
        """Update an endpoint.

        RBAC test for Keystone: identity:update_endpoint
        """
        service, endpoint = self._create_endpoint()
        new_url = data_utils.rand_url()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.endpoints_client.update_endpoint(endpoint["id"],
                                              service_id=service['id'],
                                              url=new_url)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_endpoint")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd129')
    def test_delete_endpoint(self):
        """Delete an endpoint.

        RBAC test for Keystone: identity:delete_endpoint
        """
        _, endpoint = self._create_endpoint()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.endpoints_client.delete_endpoint(endpoint['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_endpoint")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd130')
    def test_show_endpoint(self):
        """Show/Get an endpoint.

        RBAC test for Keystone: identity:get_endpoint
        """
        _, endpoint = self._create_endpoint()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.endpoints_client.show_endpoint(endpoint['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_endpoints")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd131')
    def test_list_endpoints(self):
        """Create a Domain.

        RBAC test for Keystone: identity:create_domain
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.endpoints_client.list_endpoints()
