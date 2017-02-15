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

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.identity.v2 import rbac_base

CONF = config.CONF


class IdentityServicesV2AdminRbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentityServicesV2AdminRbacTest, self).tearDown()

    @classmethod
    def setup_clients(cls):
        super(IdentityServicesV2AdminRbacTest, cls).setup_clients()
        cls.services_client = cls.os.identity_services_client

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_service")
    @decorators.idempotent_id('370050f6-d271-4fb4-abc5-4de1d6dfbad2')
    def test_create_service(self):
        """Create Service Test

        RBAC test for Identity Admin 2.0 create_service
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_service()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_service")
    @decorators.idempotent_id('f6c64fc3-6a1f-423e-af91-e411add3a384')
    def test_delete_service(self):
        """Delete Service Test

        RBAC test for Identity Admin 2.0 delete_service
        """
        service_id = self._create_service()['OS-KSADM:service']['id']

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.delete_service(service_id)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_service")
    @decorators.idempotent_id('504d62bb-97d7-445e-9d6d-b1945a7c9e08')
    def test_show_service(self):
        """Show Service Test

        RBAC test for Identity Admin 2.0 show_service
        """
        service_id = self._create_service()['OS-KSADM:service']['id']

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.show_service(service_id)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_services")
    @decorators.idempotent_id('d7dc461d-51ad-48e0-9cd2-33add1b88de9')
    def test_list_services(self):
        """List all the services

        RBAC test for Identity Admin 2.0 list_service
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.services_client.list_services()
