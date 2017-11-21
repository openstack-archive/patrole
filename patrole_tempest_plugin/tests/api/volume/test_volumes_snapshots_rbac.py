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
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesSnapshotV3RbacTest(rbac_base.BaseVolumeRbacTest):
    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(VolumesSnapshotV3RbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.snapshot:
            raise cls.skipException("Cinder volume snapshots are disabled")

    @classmethod
    def setup_clients(cls):
        super(VolumesSnapshotV3RbacTest, cls).setup_clients()
        cls.admin_snapshots_client = cls.os_admin.snapshots_v2_client

    @classmethod
    def resource_setup(cls):
        super(VolumesSnapshotV3RbacTest, cls).resource_setup()
        # Create a test shared volume for tests
        cls.volume = cls.create_volume()
        # Create a test shared snapshot for tests
        cls.snapshot = cls.create_snapshot(cls.volume['id'])

    def _list_by_param_values(self, params, with_detail=False):
        # Perform list or list_details action with given params
        # and validates result.
        if with_detail:
            self.snapshots_client.list_snapshots(
                detail=True, params=params)['snapshots']
        else:
            self.snapshots_client.list_snapshots(
                params=params)['snapshots']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:create_snapshot")
    @decorators.idempotent_id('ac7b2ee5-fbc0-4360-afc2-de8fa4881ede')
    def test_snapshot_create(self):
        # Create a temp snapshot
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_snapshot(self.volume['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_snapshot")
    @decorators.idempotent_id('93a11b40-1ba8-44d6-a196-f8d97220f796')
    def test_snapshot_get(self):
        # Get the snapshot
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.snapshots_client.show_snapshot(self.snapshot
                                            ['id'])['snapshot']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_snapshot")
    @decorators.idempotent_id('53fe8ee3-3bea-4ae8-a979-3c98ea72f620')
    def test_snapshot_update(self):
        new_desc = 'This is the new description of snapshot.'
        params = {'description': new_desc}
        # Updates snapshot with new values
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.snapshots_client.update_snapshot(
            self.snapshot['id'], **params)['snapshot']
        waiters.wait_for_volume_resource_status(
            self.admin_snapshots_client, self.snapshot['id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all_snapshots")
    @decorators.idempotent_id('e4edf0c0-2cd3-420f-b8ab-4d98a0718608')
    def test_snapshots_get_all(self):
        """list snapshots with params."""
        # Verify list snapshots by display_name filter
        params = {'name': self.snapshot['name']}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._list_by_param_values(params)

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete_snapshot")
    @decorators.idempotent_id('c7fe54ec-3b70-4772-ba11-f166d95888a3')
    def test_snapshot_delete(self):
        # Create a temp snapshot
        temp_snapshot = self.create_snapshot(self.volume['id'])
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Delete the snapshot
        self.snapshots_client.delete_snapshot(temp_snapshot['id'])
        self.admin_snapshots_client.wait_for_resource_deletion(
            temp_snapshot['id'])
