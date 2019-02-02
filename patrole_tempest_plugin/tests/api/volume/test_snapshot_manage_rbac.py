# Copyright 2017 NEC Corporation
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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class SnapshotManageRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(SnapshotManageRbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.manage_snapshot:
            raise cls.skipException("Manage snapshot tests are disabled")
        if len(CONF.volume.manage_snapshot_ref) != 2:
            msg = ("Manage snapshot ref is not correctly configured, "
                   "it should be a list of two elements")
            raise lib_exc.InvalidConfiguration(msg)

    @classmethod
    def setup_clients(cls):
        super(SnapshotManageRbacTest, cls).setup_clients()
        cls.snapshot_manage_client = \
            cls.os_primary.snapshot_manage_client_latest

    @classmethod
    def resource_setup(cls):
        super(SnapshotManageRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()
        cls.snapshot = cls.create_snapshot(volume_id=cls.volume['id'])

    @decorators.idempotent_id('bd7d62f2-e485-4626-87ef-03b7f19ee1d0')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["snapshot_extension:snapshot_manage"])
    def test_manage_snapshot_rbac(self):
        name = data_utils.rand_name(self.__class__.__name__ +
                                    '-Managed-Snapshot')
        snapshot_ref = {
            'volume_id': self.volume['id'],
            'ref': {CONF.volume.manage_snapshot_ref[0]:
                    CONF.volume.manage_snapshot_ref[1] % self.snapshot['id']},
            'name': name
        }
        with self.override_role():
            snapshot = self.snapshot_manage_client.manage_snapshot(
                **snapshot_ref)['snapshot']
        self.addCleanup(self.delete_snapshot, snapshot['id'],
                        self.snapshots_client)
        waiters.wait_for_volume_resource_status(self.snapshots_client,
                                                snapshot['id'],
                                                'available')

    @decorators.idempotent_id('4a2e8934-9c0b-434e-8f0b-e18b9aff126f')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["snapshot_extension:snapshot_unmanage"])
    def test_unmanage_snapshot_rbac(self):
        with self.override_role():
            self.snapshots_client.unmanage_snapshot(self.snapshot['id'])
        self.snapshots_client.wait_for_resource_deletion(
            self.snapshot['id'])
