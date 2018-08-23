# Copyright 2017 NEC Corporation.
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

from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class BaseGroupSnapshotsRbacTest(rbac_base.BaseVolumeRbacTest):

    def _create_group_snapshot(self, **kwargs):
        if 'name' not in kwargs:
            kwargs['name'] = data_utils.rand_name(
                self.__class__.__name__ + '-Group_Snapshot')
        group_snapshot = self.group_snapshots_client.create_group_snapshot(
            **kwargs)['group_snapshot']
        group_snapshot['group_id'] = kwargs['group_id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_group_snapshot, group_snapshot)
        waiters.wait_for_volume_resource_status(
            self.group_snapshots_client, group_snapshot['id'], 'available')
        snapshots = self.snapshots_client.list_snapshots(
            detail=True)['snapshots']
        for snap in snapshots:
            if self.vol['id'] == snap['volume_id']:
                waiters.wait_for_volume_resource_status(
                    self.snapshots_client, snap['id'], 'available')
        return group_snapshot

    def _delete_group_snapshot(self, group_snapshot):
        self.group_snapshots_client.delete_group_snapshot(group_snapshot['id'])
        vols = self.volumes_client.list_volumes(detail=True)['volumes']
        snapshots = self.snapshots_client.list_snapshots(
            detail=True)['snapshots']
        for vol in vols:
            for snap in snapshots:
                if (vol['group_id'] == group_snapshot['group_id'] and
                        vol['id'] == snap['volume_id']):
                    self.snapshots_client.wait_for_resource_deletion(
                        snap['id'])
        self.group_snapshots_client.wait_for_resource_deletion(
            group_snapshot['id'])


class GroupSnaphotsV314RbacTest(BaseGroupSnapshotsRbacTest):
    _api_version = 3
    min_microversion = '3.14'
    max_microversion = 'latest'

    @classmethod
    def skip_checks(cls):
        super(GroupSnaphotsV314RbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('groupsnapshot', 'volume'):
            msg = "%s skipped as group snapshots not enabled." % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(GroupSnaphotsV314RbacTest, cls).setup_clients()
        cls.group_snapshot_client = \
            cls.os_primary.group_snapshots_v3_client

    def setUp(self):
        super(GroupSnaphotsV314RbacTest, self).setUp()
        self.volume_type = self.create_volume_type()
        self.group_type = self.create_group_type()
        self.grp = self.create_group(group_type=self.group_type['id'],
                                     volume_types=[self.volume_type['id']])
        self.vol = self.create_volume(volume_type=self.volume_type['id'],
                                      group_id=self.grp['id'])

    @decorators.idempotent_id('653df0e8-d90a-474a-a5ce-3c2339aff7ba')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:create_group_snapshot"]
    )
    def test_create_group_snapshot(self):
        with self.rbac_utils.override_role(self):
            name = data_utils.rand_name(
                self.__class__.__name__ + '-Group_Snapshot')
            group_snapshot = self.group_snapshots_client.create_group_snapshot(
                name=name, group_id=self.grp['id'])['group_snapshot']
        group_snapshot['group_id'] = self.grp['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_group_snapshot, group_snapshot)
        waiters.wait_for_volume_resource_status(
            self.group_snapshots_client, group_snapshot['id'], 'available')
        snapshots = self.snapshots_client.list_snapshots(
            detail=True)['snapshots']
        for snap in snapshots:
            if self.vol['id'] == snap['volume_id']:
                waiters.wait_for_volume_resource_status(
                    self.snapshots_client, snap['id'], 'available')

    @decorators.idempotent_id('8b966844-4421-4f73-940b-9157cb878331')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:get_group_snapshot"]
    )
    def test_show_group_snapshot_rbac(self):
        group_snapshot_name = data_utils.rand_name('group_snapshot')
        group_snapshot = self._create_group_snapshot(group_id=self.grp['id'],
                                                     name=group_snapshot_name)
        with self.rbac_utils.override_role(self):
            self.group_snapshots_client.show_group_snapshot(
                group_snapshot['id'])

    @decorators.idempotent_id('e9de6dae-1efb-47cd-a3a8-d1f4b8f9f3ff')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:get_all_group_snapshots"]
    )
    def test_list_group_snapshot_rbac(self):
        with self.rbac_utils.override_role(self):
            self.group_snapshots_client.list_group_snapshots()

    @decorators.idempotent_id('cf2e25ee-ca58-4ad6-b98d-33235c77db7b')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:delete_group_snapshot"]
        )
    def test_delete_group_snapshot_rbac(self):
        group_snapshot_name = data_utils.rand_name('group_snapshot')
        group_snapshot = self._create_group_snapshot(group_id=self.grp['id'],
                                                     name=group_snapshot_name)
        with self.rbac_utils.override_role(self):
            self.group_snapshots_client.delete_group_snapshot(
                group_snapshot['id'])
        vols = self.volumes_client.list_volumes(detail=True)['volumes']
        snapshots = self.snapshots_client.list_snapshots(
            detail=True)['snapshots']
        for vol in vols:
            for snap in snapshots:
                if (vol['group_id'] == group_snapshot['group_id'] and
                        vol['id'] == snap['volume_id']):
                    self.snapshots_client.wait_for_resource_deletion(
                        snap['id'])
        self.group_snapshots_client.wait_for_resource_deletion(
            group_snapshot['id'])


class GroupSnaphotsV319RbacTest(BaseGroupSnapshotsRbacTest):
    _api_version = 3
    min_microversion = '3.19'
    max_microversion = 'latest'

    @classmethod
    def skip_checks(cls):
        super(GroupSnaphotsV319RbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('groupsnapshot', 'volume'):
            msg = "%s skipped as group snapshots not enabled." % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(GroupSnaphotsV319RbacTest, cls).setup_clients()
        cls.group_snapshot_client = \
            cls.os_primary.group_snapshots_v3_client

    def setUp(self):
        super(GroupSnaphotsV319RbacTest, self).setUp()
        self.volume_type = self.create_volume_type()
        self.group_type = self.create_group_type()
        self.grp = self.create_group(group_type=self.group_type['id'],
                                     volume_types=[self.volume_type['id']])
        self.vol = self.create_volume(volume_type=self.volume_type['id'],
                                      group_id=self.grp['id'])

    @decorators.idempotent_id('3f0c842e-0c72-4f5e-a9c2-281070be3e2c')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:reset_group_snapshot_status"]
        )
    def test_reset_group_snapshot_rbac(self):
        group_snapshot_name = data_utils.rand_name('group_snapshot')
        group_snapshot = self._create_group_snapshot(group_id=self.grp['id'],
                                                     name=group_snapshot_name)
        with self.rbac_utils.override_role(self):
            self.group_snapshots_client.reset_group_snapshot_status(
                group_snapshot['id'], 'error')

        waiters.wait_for_volume_resource_status(
            self.group_snapshots_client, group_snapshot['id'], 'error')
