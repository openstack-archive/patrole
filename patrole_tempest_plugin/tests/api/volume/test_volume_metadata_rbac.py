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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumeMetadataV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def resource_setup(cls):
        super(VolumeMetadataV3RbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()
        cls.image_id = CONF.compute.image_ref

    def _add_metadata(self, volume):
        # Create metadata for the volume.
        metadata = {"key1": "value1"}
        self.volumes_client.create_volume_metadata(
            self.volume['id'], metadata)['metadata']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.volumes_client.delete_volume_metadata_item,
                        self.volume['id'], "key1")

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:create_volume_metadata"])
    @decorators.idempotent_id('232bbb8b-4c29-44dc-9077-b1398c20b738')
    def test_create_volume_metadata(self):
        with self.override_role():
            self._add_metadata(self.volume)

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_volume_metadata"])
    @decorators.idempotent_id('87ea37d9-23ab-47b2-a59c-16fc4d2c6dfa')
    def test_show_volume_metadata(self):
        with self.override_role():
            self.volumes_client.show_volume_metadata(
                self.volume['id'])['metadata']

    @decorators.idempotent_id('5c0f4c19-b448-4f51-9224-dad5faddc3bb')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_volume_metadata"])
    def test_show_volume_metadata_item(self):
        self._add_metadata(self.volume)

        with self.override_role():
            self.volumes_client.show_volume_metadata_item(
                self.volume['id'], "key1")

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:delete_volume_metadata"])
    @decorators.idempotent_id('7498dfc1-9db2-4423-ad20-e6dcb25d1beb')
    def test_delete_volume_metadata_item(self):
        self._add_metadata(self.volume)

        with self.override_role():
            self.volumes_client.delete_volume_metadata_item(self.volume['id'],
                                                            "key1")

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:update_volume_metadata"])
    @decorators.idempotent_id('8ce2ff80-99ba-49ae-9bb1-7e96729ee5af')
    def test_update_volume_metadata_item(self):
        self._add_metadata(self.volume)
        updated_metadata_item = {"key1": "value1_update"}
        with self.override_role():
            self.volumes_client.update_volume_metadata_item(
                self.volume['id'], "key1", updated_metadata_item)['meta']

    @decorators.idempotent_id('a231b445-97a5-4657-b05f-245895e88da9')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:update_volume_metadata"])
    def test_update_volume_metadata(self):
        self._add_metadata(self.volume)
        updated_metadata = {"key1": "value1"}
        with self.override_role():
            self.volumes_client.update_volume_metadata(self.volume['id'],
                                                       updated_metadata)

    @decorators.idempotent_id('39e8f82c-f1fc-4905-bf47-177ce2f71bb9')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_image_metadata"])
    def test_list_volumes_details_image_metadata(self):
        self.volumes_client.update_volume_image_metadata(
            self.volume['id'], image_id=self.image_id)
        self.addCleanup(self.volumes_client.delete_volume_image_metadata,
                        self.volume['id'], 'image_id')

        with self.override_role():
            resp_body = self.volumes_client.list_volumes(detail=True)[
                'volumes']
        expected_attr = 'volume_image_metadata'
        if expected_attr not in resp_body[0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @decorators.idempotent_id('53f94d52-0dd5-42cf-a3a4-59b35150b3d5')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_image_metadata"])
    def test_show_volume_details_image_metadata(self):
        self.volumes_client.update_volume_image_metadata(
            self.volume['id'], image_id=self.image_id)
        self.addCleanup(self.volumes_client.delete_volume_image_metadata,
                        self.volume['id'], 'image_id')

        with self.override_role():
            resp_body = self.volumes_client.show_volume(self.volume['id'])[
                'volume']
        expected_attr = 'volume_image_metadata'
        if expected_attr not in resp_body:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @decorators.idempotent_id('a9d9e825-5ea3-42e6-96f3-7ac4e97b2ed0')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_image_metadata"])
    def test_update_volume_image_metadata(self):
        with self.override_role():
            self.volumes_client.update_volume_image_metadata(
                self.volume['id'], image_id=self.image_id)
        self.addCleanup(self.volumes_client.delete_volume_image_metadata,
                        self.volume['id'], 'image_id')

    @decorators.idempotent_id('a41c8eed-2051-4a25-b401-df036faacbdc')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_image_metadata"])
    def test_delete_volume_image_metadata(self):
        self.volumes_client.update_volume_image_metadata(
            self.volume['id'], image_id=self.image_id)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.volumes_client.delete_volume_image_metadata,
                        self.volume['id'], 'image_id')

        with self.override_role():
            self.volumes_client.delete_volume_image_metadata(self.volume['id'],
                                                             'image_id')
