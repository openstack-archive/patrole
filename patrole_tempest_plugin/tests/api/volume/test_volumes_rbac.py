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
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class VolumesRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(VolumesRbacTest, cls).setup_clients()
        cls.client = cls.volumes_client

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(VolumesRbacTest, self).tearDown()

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_admin_actions:reset_status")
    @decorators.idempotent_id('4b3dad7d-0e73-4839-8781-796dd3d7af1d')
    def test_volume_reset_status(self):
        volume = self.create_volume()
        # Test volume reset status : available->error->available
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.reset_volume_status(volume['id'], status='error')
        self.client.reset_volume_status(volume['id'], status='availble')

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_admin_actions:force_delete")
    @decorators.idempotent_id('a312a937-6abf-4b91-a950-747086cbce48')
    def test_volume_force_delete_when_volume_is_error(self):
        volume = self.create_volume()
        self.client.reset_volume_status(volume['id'], status='error')
        # Test force delete when status of volume is error
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.force_delete_volume(volume['id'])
        self.client.wait_for_resource_deletion(volume['id'])


class VolumesV3RbacTest(VolumesRbacTest):
    _api_version = 3
