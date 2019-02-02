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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesBasicCrudV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def resource_setup(cls):
        super(VolumesBasicCrudV3RbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:create"])
    @decorators.idempotent_id('426b08ef-6394-4d06-9128-965d5a6c38ef')
    def test_create_volume(self):
        name = data_utils.rand_name(self.__class__.__name__ + '-Volume')
        size = CONF.volume.volume_size

        with self.override_role():
            volume = self.volumes_client.create_volume(name=name, size=size)[
                'volume']
        # Use helper in base Tempest volume class which waits for deletion.
        self.addCleanup(self.delete_volume, self.volumes_client, volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')

    @decorators.idempotent_id('a009e6dc-e8bf-4412-99f5-8e45cffcffec')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:create_from_image"])
    def test_create_volume_from_image(self):
        name = data_utils.rand_name(self.__class__.__name__ + '-Volume')
        size = CONF.volume.volume_size
        img_uuid = CONF.compute.image_ref

        with self.override_role():
            volume = self.volumes_client.create_volume(
                name=name, size=size, imageRef=img_uuid)['volume']
        # Use helper in base Tempest volume class which waits for deletion.
        self.addCleanup(self.delete_volume, self.volumes_client, volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:delete"])
    @decorators.idempotent_id('6de9f9c2-509f-4558-867b-af21c7163be4')
    def test_delete_volume(self):
        volume = self.create_volume()
        with self.override_role():
            self.volumes_client.delete_volume(volume['id'])
        self.volumes_client.wait_for_resource_deletion(volume['id'])

    @rbac_rule_validation.action(service="cinder", rules=["volume:get"])
    @decorators.idempotent_id('c4c3fdd5-b1b1-49c3-b977-a9f40ee9257a')
    def test_show_volume(self):
        with self.override_role():
            self.volumes_client.show_volume(self.volume['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_all"])
    @decorators.idempotent_id('e3ab7906-b04b-4c45-aa11-1104d302f940')
    def test_list_volumes(self):
        with self.override_role():
            self.volumes_client.list_volumes()

    @decorators.idempotent_id('9b6d5beb-254f-4f1b-9906-0bdce4042f53')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_all"])
    def test_list_volumes_with_details(self):
        with self.override_role():
            self.volumes_client.list_volumes(detail=True)

    @rbac_rule_validation.action(service="cinder", rules=["volume:update"])
    @decorators.idempotent_id('b751b889-9a9b-40d8-ae7d-4b0f65e71ac7')
    def test_update_volume(self):
        update_name = data_utils.rand_name(self.__class__.__name__ + 'volume')
        with self.override_role():
            self.volumes_client.update_volume(self.volume['id'],
                                              name=update_name)
