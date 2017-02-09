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
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base

CONF = config.CONF


class IdentitySericesV3AdminRbacTest(rbac_base.BaseIdentityV3RbacAdminTest):

    def tearDown(self):
        """Reverts user back to admin for cleanup."""
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentitySericesV3AdminRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_service")
    @test.idempotent_id('9a4bb317-f0bb-4005-8df0-4b672885b7c8')
    def test_create_service(self):
        """Create a service.

        RBAC test for Keystone: identity:create_service
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_service()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_service")
    @test.idempotent_id('b39447d1-2cf6-40e5-a899-46f287f2ecf0')
    def test_update_service(self):
        """Update a service.

        RBAC test for Keystone: identity:update_service
        """
        service = self._create_service()
        new_name = data_utils.rand_name('new_test_name')

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.update_service(service['id'],
                                            service=service,
                                            name=new_name,
                                            type=service['type'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_service")
    @test.idempotent_id('177b991a-438d-4bef-8e9f-9c6cc5a1c9e8')
    def test_delete_service(self):
        """Delete a service.

        RBAC test for Keystone: identity:delete_service
        """
        service = self._create_service()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.delete_service(service['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_service")
    @test.idempotent_id('d89a9ac6-cd53-428d-84c0-5bc71f4a432d')
    def test_show_service(self):
        """Show/Get a service.

        RBAC test for Keystone: identity:get_service
        """
        service = self._create_service()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.show_service(service['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_services")
    @test.idempotent_id('706e6bea-3385-4718-919c-0b5121395806')
    def test_list_services(self):
        """list all services.

        RBAC test for Keystone: identity:list_services
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.list_services()
