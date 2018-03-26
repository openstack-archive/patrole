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

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class SnapshotMetadataV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(SnapshotMetadataV3RbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.snapshot:
            raise cls.skipException("Cinder snapshot feature disabled")

    @classmethod
    def resource_setup(cls):
        super(SnapshotMetadataV3RbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()
        # Create a snapshot
        cls.snapshot = cls.create_snapshot(volume_id=cls.volume['id'])
        cls.snapshot_id = cls.snapshot['id']

    @classmethod
    def _create_test_snapshot_metadata(self):
        # Create test snapshot metadata
        metadata = {"key1": "value1",
                    "key2": "value2",
                    "key3": "value3"}
        self.snapshots_client.create_snapshot_metadata(
            self.snapshot_id, metadata)['metadata']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_snapshot_metadata")
    @decorators.idempotent_id('f6912bb1-62e6-483d-bcd0-e98c1641f4c3')
    def test_get_snapshot_metadata(self):
        # Create volume and snapshot metadata
        self._create_test_snapshot_metadata()
        # Get metadata for the snapshot
        with self.rbac_utils.override_role(self):
            self.snapshots_client.show_snapshot_metadata(
                self.snapshot_id)

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_tenant_attribute")
    @decorators.idempotent_id('e2c73b00-0c19-4bb7-8c61-d84b1a223ed1')
    def test_get_snapshot_metadata_for_volume_tenant(self):
        # Create volume and snapshot metadata
        self._create_test_snapshot_metadata()
        # Get the metadata of the snapshot
        with self.rbac_utils.override_role(self):
            self.snapshots_client.show_snapshot_metadata(
                self.snapshot_id)['metadata']

    @decorators.idempotent_id('7ea597f6-c544-4b10-aab0-ff68f595fb06')
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_snapshot_metadata")
    def test_update_snapshot_metadata(self):
        self._create_test_snapshot_metadata()
        with self.rbac_utils.override_role(self):
            update = {"key3": "value3_update",
                      "key4": "value4"}
            self.snapshots_client.update_snapshot_metadata(
                self.snapshot['id'], metadata=update)

    @decorators.idempotent_id('93068d02-0131-4dd3-af16-fc40d7128d93')
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_snapshot_metadata")
    def test_show_snapshot_metadata_item(self):
        self._create_test_snapshot_metadata()
        with self.rbac_utils.override_role(self):
            self.snapshots_client.show_snapshot_metadata_item(
                self.snapshot['id'], "key3")['meta']

    @decorators.idempotent_id('1f8f43e7-da31-4128-bb3c-73fc548650e3')
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_snapshot_metadata")
    def test_update_snapshot_metadata_item(self):
        update_item = {"key3": "value3_update"}
        self._create_test_snapshot_metadata()
        with self.rbac_utils.override_role(self):
            self.snapshots_client.update_snapshot_metadata_item(
                self.snapshot['id'], "key3", meta=update_item)['meta']

    @decorators.idempotent_id('3ec32516-f7cd-4f88-b78a-ddee67492071')
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete_snapshot_metadata")
    def test_delete_snapshot_metadata_item(self):
        self._create_test_snapshot_metadata()
        with self.rbac_utils.override_role(self):
            self.snapshots_client.delete_snapshot_metadata_item(
                self.snapshot['id'], "key1")
