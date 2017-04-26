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


class IdentityServicesV2AdminRbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('370050f6-d271-4fb4-abc5-4de1d6dfbad2')
    def test_create_service(self):
        """Create Service Test

        RBAC test for Identity v2 create_service
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.setup_test_service()

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('f6c64fc3-6a1f-423e-af91-e411add3a384')
    def test_delete_service(self):
        """Delete Service Test

        RBAC test for Identity v2 delete_service
        """
        service_id = self.setup_test_service()['id']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.services_client.delete_service(service_id)

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('504d62bb-97d7-445e-9d6d-b1945a7c9e08')
    def test_show_service(self):
        """Show Service Test

        RBAC test for Identity v2 show_service
        """
        service_id = self.setup_test_service()['id']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.services_client.show_service(service_id)

    @rbac_rule_validation.action(service="keystone",
                                 admin_only=True)
    @decorators.idempotent_id('d7dc461d-51ad-48e0-9cd2-33add1b88de9')
    def test_list_services(self):
        """List all the services

        RBAC test for Identity v2 list_service
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.services_client.list_services()
