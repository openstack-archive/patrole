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

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class VolumeMetadataRbacTest(rbac_base.BaseVolumeRbacTest):
    @classmethod
    def setup_clients(cls):
        super(VolumeMetadataRbacTest, cls).setup_clients()
        cls.client = cls.volumes_client

    def _add_metadata(self, volume):
        # Create metadata for the volume
        metadata = {"key1": "value1",
                    "key2": "value2",
                    "key3": "value3",
                    "key4": "<value&special_chars>"}
        self.volumes_client.create_volume_metadata(volume['id'],
                                                   metadata)['metadata']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_volume_metadata")
    @decorators.idempotent_id('232bbb8b-4c29-44dc-9077-b1398c20b738')
    def test_create_volume_metadata(self):
        volume = self.create_volume()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._add_metadata(volume)

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get")
    @decorators.idempotent_id('87ea37d9-23ab-47b2-a59c-16fc4d2c6dfa')
    def test_get_volume_metadata(self):
        volume = self.create_volume()
        self._add_metadata(volume)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.show_volume_metadata(volume['id'])['metadata']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete_volume_metadata")
    @decorators.idempotent_id('7498dfc1-9db2-4423-ad20-e6dcb25d1beb')
    def test_delete_volume_metadata(self):
        volume = self.create_volume()
        self._add_metadata(volume)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.delete_volume_metadata_item(volume['id'],
                                                        "key1")

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_volume_metadata")
    @decorators.idempotent_id('8ce2ff80-99ba-49ae-9bb1-7e96729ee5af')
    def test_update_volume_metadata(self):
        volume = self.create_volume()
        self._add_metadata(volume)
        # Metadata to update
        update_item = {"key3": "value3_update"}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.update_volume_metadata_item(
            volume['id'], "key3", update_item)['meta']


class VolumeMetadataV3RbacTest(VolumeMetadataRbacTest):
    _api_version = 3
