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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumesV2BasicCrudRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def resource_setup(cls):
        super(VolumesV2BasicCrudRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:create")
    @decorators.idempotent_id('426b08ef-6394-4d06-9128-965d5a6c38ef')
    def test_create_volume(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_volume()

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete")
    @decorators.idempotent_id('6de9f9c2-509f-4558-867b-af21c7163be4')
    def test_delete_volume(self):
        volume = self.create_volume()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.delete_volume(volume['id'])

    @rbac_rule_validation.action(service="cinder", rule="volume:get")
    @decorators.idempotent_id('c4c3fdd5-b1b1-49c3-b977-a9f40ee9257a')
    def test_get_volume(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.show_volume(self.volume['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all")
    @decorators.idempotent_id('e3ab7906-b04b-4c45-aa11-1104d302f940')
    def test_volume_list(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.list_volumes()

    @rbac_rule_validation.action(service="cinder", rule="volume:update")
    @decorators.idempotent_id('b751b889-9a9b-40d8-ae7d-4b0f65e71ac7')
    def test_update_volume(self):
        update_name = data_utils.rand_name('volume')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.update_volume(self.volume['id'],
                                          name=update_name)

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_image_metadata")
    @decorators.idempotent_id('3d48ca91-f02b-4616-a69d-4a8b296c8529')
    def test_volume_list_image_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.list_volumes(detail=True)


class VolumesV3BasicCrudRbacTest(VolumesV2BasicCrudRbacTest):
    _api_version = 3
