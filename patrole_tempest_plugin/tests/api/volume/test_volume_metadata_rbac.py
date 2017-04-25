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
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumeMetadataRbacTest(rbac_base.BaseVolumeRbacTest):
    @classmethod
    def setup_clients(cls):
        super(VolumeMetadataRbacTest, cls).setup_clients()
        cls.client = cls.volumes_client
        if CONF.image_feature_enabled.api_v1:
            cls.image_client = cls.os_primary.image_client
        elif CONF.image_feature_enabled.api_v2:
            cls.image_client = cls.os_primary.image_client_v2
        cls.image_id = CONF.compute.image_ref

    @classmethod
    def resource_setup(cls):
        super(VolumeMetadataRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()
        cls._add_metadata(cls.volume)
        cls.image_id = CONF.compute.image_ref

    @classmethod
    def _add_metadata(cls, volume):
        # Create metadata for the volume
        metadata = {"key1": "value1",
                    "key2": "value2",
                    "key3": "value3",
                    "key4": "<value&special_chars>"}
        cls.client.create_volume_metadata(cls.volume['id'],
                                          metadata)['metadata']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_volume_metadata")
    @decorators.idempotent_id('232bbb8b-4c29-44dc-9077-b1398c20b738')
    def test_create_volume_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._add_metadata(self.volume)

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get")
    @decorators.idempotent_id('87ea37d9-23ab-47b2-a59c-16fc4d2c6dfa')
    def test_get_volume_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_volume_metadata(self.volume['id'])['metadata']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete_volume_metadata")
    @decorators.idempotent_id('7498dfc1-9db2-4423-ad20-e6dcb25d1beb')
    def test_delete_volume_metadata_item(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_volume_metadata_item(self.volume['id'], "key1")

    @decorators.idempotent_id('a41c8eed-2051-4a25-b401-df036faacbdc')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume:delete_volume_metadata")
    def test_delete_volume_image_metadata(self):
        self.client.update_volume_image_metadata(self.volume['id'],
                                                 image_id=self.image_id)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_volume_image_metadata(self.volume['id'], 'image_id')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_volume_metadata")
    @decorators.idempotent_id('8ce2ff80-99ba-49ae-9bb1-7e96729ee5af')
    def test_update_volume_metadata_item(self):
        # Metadata to update
        update_item = {"key3": "value3_update"}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_volume_metadata_item(self.volume['id'], "key3",
                                                update_item)['meta']

    @decorators.idempotent_id('a231b445-97a5-4657-b05f-245895e88da9')
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_volume_metadata")
    def test_update_volume_metadata(self):
        # Metadata to update
        update = {"key1": "value1",
                  "key3": "value3"}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_volume_metadata(self.volume['id'], update)

    @decorators.idempotent_id('a9d9e825-5ea3-42e6-96f3-7ac4e97b2ed0')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume:update_volume_metadata")
    def test_update_volume_image_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_volume_image_metadata(self.volume['id'],
                                                 image_id=self.image_id)


class VolumeMetadataV3RbacTest(VolumeMetadataRbacTest):
    _api_version = 3
