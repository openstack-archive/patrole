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

from tempest.common import waiters
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumesTransfersV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(VolumesTransfersV3RbacTest, cls).setup_clients()
        cls.transfers_client = cls.os_primary.volume_transfers_v2_client

    @classmethod
    def resource_setup(cls):
        super(VolumesTransfersV3RbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _delete_transfer(self, transfer):
        # Volume from create_volume_transfer test may get stuck in
        # 'awaiting-transfer' state, preventing cleanup and causing
        # the test to fail.
        test_utils.call_and_ignore_notfound_exc(
            self.transfers_client.delete_volume_transfer, transfer['id'])
        waiters.wait_for_volume_resource_status(
            self.volumes_client, self.volume['id'], 'available')

    def _create_transfer(self):
        transfer = self.transfers_client.create_volume_transfer(
            volume_id=self.volume['id'])['transfer']
        self.addCleanup(self._delete_transfer, transfer)
        return transfer

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:create_transfer")
    @decorators.idempotent_id('25413af4-468d-48ff-94ca-4436f8526b3e')
    def test_create_volume_transfer(self):
        with self.rbac_utils.override_role(self):
            self._create_transfer()
        waiters.wait_for_volume_resource_status(
            self.volumes_client, self.volume['id'], 'awaiting-transfer')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_transfer")
    @decorators.idempotent_id('7a0925d3-ed97-4c25-8299-e5cdabe2eb55')
    def test_get_volume_transfer(self):
        transfer = self._create_transfer()
        waiters.wait_for_volume_resource_status(
            self.volumes_client, self.volume['id'], 'awaiting-transfer')

        with self.rbac_utils.override_role(self):
            self.transfers_client.show_volume_transfer(transfer['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all_transfers")
    @decorators.idempotent_id('02a06f2b-5040-49e2-b2b7-619a7db59603')
    def test_list_volume_transfers(self):
        with self.rbac_utils.override_role(self):
            self.transfers_client.list_volume_transfers()

    @decorators.idempotent_id('e84e45b0-9872-40bf-bf44-971266161a86')
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all_transfers")
    def test_list_volume_transfers_details(self):
        with self.rbac_utils.override_role(self):
            self.transfers_client.list_volume_transfers(detail=True)

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:accept_transfer")
    @decorators.idempotent_id('987f2a11-d657-4984-a6c9-28f06c1cd014')
    def test_accept_volume_transfer(self):
        transfer = self._create_transfer()
        waiters.wait_for_volume_resource_status(
            self.volumes_client, self.volume['id'], 'awaiting-transfer')

        with self.rbac_utils.override_role(self):
            self.transfers_client.accept_volume_transfer(
                transfer['id'], auth_key=transfer['auth_key'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                self.volume['id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete_transfer")
    @decorators.idempotent_id('4672187e-7fff-454b-832a-5c8865dda868')
    def test_delete_volume_transfer(self):
        transfer = self._create_transfer()
        waiters.wait_for_volume_resource_status(
            self.volumes_client, self.volume['id'], 'awaiting-transfer')

        with self.rbac_utils.override_role(self):
            self.transfers_client.delete_volume_transfer(transfer['id'])
        waiters.wait_for_volume_resource_status(
            self.volumes_client, self.volume['id'], 'available')
