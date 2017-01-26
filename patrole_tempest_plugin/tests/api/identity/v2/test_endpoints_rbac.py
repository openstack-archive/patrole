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
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.identity.v2 import rbac_base

CONF = config.CONF


class IdentityEndpointsV2AdminRbacTest(rbac_base.BaseIdentityV2AdminRbacTest):

    @classmethod
    def setup_clients(cls):
        super(IdentityEndpointsV2AdminRbacTest, cls).setup_clients()
        cls.endpoints_client = cls.os.endpoints_client

    @classmethod
    def resource_setup(cls):
        super(IdentityEndpointsV2AdminRbacTest, cls).resource_setup()
        cls.region = data_utils.rand_name('region')
        cls.public_url = data_utils.rand_url()
        cls.admin_url = data_utils.rand_url()
        cls.internal_url = data_utils.rand_url()

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(IdentityEndpointsV2AdminRbacTest, self).tearDown()

    def _create_endpoint(self):
        self._create_service()
        endpoint = self.endpoints_client.create_endpoint(
            service_id=self.service['OS-KSADM:service']['id'],
            region=self.region,
            publicurl=self.public_url,
            adminurl=self.admin_url,
            internalurl=self.internal_url
        )
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.endpoints_client.delete_endpoint,
                        endpoint['endpoint']['id'])
        return endpoint

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_endpoint")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd124')
    def test_create_endpoint(self):

        """Create Endpoint Test

        RBAC test for Identity Admin 2.0 create_endpoint
        """

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_endpoint()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_endpoint")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd125')
    def test_delete_endpoint(self):

        """Delete Endpoint Test

        RBAC test for Identity Admin 2.0 delete_endpoint
        """

        endpoint = self._create_endpoint()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.endpoints_client.delete_endpoint(endpoint['endpoint']['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_endpoints")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd126')
    def test_list_endpoints(self):

        """List Endpoints Test

        RBAC test for Identity Admin 2.0 list_endpoint
        """

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.endpoints_client.list_endpoints()
