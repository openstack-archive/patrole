# Copyright 2016 AT&T Corp
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

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesTransfersRbacTest(rbac_base.BaseVolumeRbacTest):

    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def setup_clients(cls):
        super(VolumesTransfersRbacTest, cls).setup_clients()
        cls.client = cls.volumes_client
        cls.alt_client = cls.os_alt.volumes_client
        cls.alt_tenant_id = cls.alt_client.tenant_id

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(VolumesTransfersRbacTest, self).tearDown()

    @classmethod
    def resource_setup(cls):
        super(VolumesTransfersRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _delete_transfer(self, transfer):
        # Volume from create_volume_transfer test may get stuck in
        # 'awaiting-transfer' state, preventing cleanup and causing
        # the test to fail
        test_utils.call_and_ignore_notfound_exc(
            self.client.delete_volume_transfer, transfer['id'])
        waiters.wait_for_volume_status(self.client, self.volume['id'],
                                       'available')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:create_transfer")
    @decorators.idempotent_id('25413af4-468d-48ff-94ca-4436f8526b3e')
    def test_create_volume_transfer(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        transfer = self.client.create_volume_transfer(
            volume_id=self.volume['id'])['transfer']
        self.addCleanup(self._delete_transfer, transfer)

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all_transfers")
    @decorators.idempotent_id('7a0925d3-ed97-4c25-8299-e5cdabe2eb55')
    def test_get_volume_transfer(self):
        transfer = self.client.create_volume_transfer(
            volume_id=self.volume['id'])['transfer']
        self.addCleanup(self._delete_transfer, transfer)
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_volume_transfer(transfer['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all_transfers")
    @decorators.idempotent_id('02a06f2b-5040-49e2-b2b7-619a7db59603')
    def test_list_volume_transfers(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_volume_transfers()

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:accept_transfer")
    @decorators.idempotent_id('987f2a11-d657-4984-a6c9-28f06c1cd014')
    def test_accept_volume_transfer(self):
        transfer = self.client.create_volume_transfer(
            volume_id=self.volume['id'])['transfer']
        self.addCleanup(self._delete_transfer, transfer)
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.accept_volume_transfer(transfer['id'],
                                           auth_key=transfer['auth_key'])


class VolumesTransfersV3RbacTest(VolumesTransfersRbacTest):
    _api_version = 3
