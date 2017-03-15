# Copyright 2017 AT&T Corp
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


class VolumesListRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(VolumesListRbacTest, cls).setup_clients()
        cls.client = cls.os.volumes_client

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:get_all")
    @decorators.idempotent_id('e3ab7906-b04b-4c45-aa11-1104d302f940')
    def test_volume_list(self):
        # Get a list of Volumes
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_volumes()

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:get_volumes_image_metadata")
    @decorators.idempotent_id('3d48ca91-f02b-4616-a69d-4a8b296c8529')
    def test_volume_list_image_metadata(self):
        # Get a list of Volumes
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_volumes(detail=True)


class VolumeListV3RbacTest(VolumesListRbacTest):
    _api_version = 3
