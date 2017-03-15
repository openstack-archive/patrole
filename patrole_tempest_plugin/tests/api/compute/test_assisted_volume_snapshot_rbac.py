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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators


class AssistedVolumeSnapshotRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """Assisted volume snapshot tests.

    Test class for create and delete
    """

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(AssistedVolumeSnapshotRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    def _create_and_attach(self):
        self.server = self.create_test_server(wait_until='ACTIVE')
        self.volume = self.create_volume()
        self.attachment = self.attach_volume(
            self.server, self.volume)

    @decorators.skip_because(bug="1668407")
    @decorators.idempotent_id('74f64957-912d-4537-983b-cea4a31c5c9f')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-assisted-volume-snapshots:create")
    def test_assisted_volume_snapshot_create(self):
        """Create Role Test.

        RBAC test for assisted volume snapshot role-create
        """
        self._create_and_attach()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.assisted_volume_snapshot_client.\
            create_volume_attachments(self.volume['id'],
                                      data_utils.rand_uuid())

    @decorators.skip_because(bug="1668407")
    @decorators.idempotent_id('01323040-c5df-4e15-8b1a-3df98fa7d998')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-assisted-volume-snapshots:delete")
    def test_assisted_volume_snapshot_delete(self):
        """Delete Role Test.

        RBAC test for assisted volume snapshot role-delete
        """
        self._create_and_attach()
        snapshot_id = data_utils.rand_uuid()
        self.assisted_volume_snapshot_client.\
            create_volume_attachments(self.volume['id'], snapshot_id)
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.assisted_volume_snapshot_client.\
            delete_volume_attachments(snapshot_id, self.volume['id'])
