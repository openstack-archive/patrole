#    Copyright 2017 AT&T Corporation.
#    All Rights Reserved.
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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class KeypairsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(KeypairsRbacTest, cls).setup_clients()
        cls.client = cls.keypairs_client

    def _create_keypair(self):
        key_name = data_utils.rand_name(self.__class__.__name__ + '-key')
        keypair = self.client.create_keypair(name=key_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.client.delete_keypair,
                        key_name)
        return keypair

    @decorators.idempotent_id('16e0ae81-e05f-48cd-b253-cf31ab0732f0')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-keypairs:create")
    def test_create_keypair(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_keypair()

    @decorators.idempotent_id('85a5eb99-40ec-4e77-9358-bee2cdf9d7df')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-keypairs:show")
    def test_show_keypair(self):
        kp_name = self._create_keypair()['keypair']['name']
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_keypair(kp_name)

    @decorators.idempotent_id('6bff9f1c-b809-43c1-8d63-61fbd19d49d3')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-keypairs:delete")
    def test_delete_keypair(self):
        kp_name = self._create_keypair()['keypair']['name']
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_keypair(kp_name)

    @decorators.idempotent_id('6bb31346-ff7f-4b10-978e-170ac5fcfa3e')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-keypairs:index")
    def test_index_keypair(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_keypairs()
