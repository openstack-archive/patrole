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
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class CreateDeleteVolumeRbacTest(rbac_base.BaseVolumeRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(CreateDeleteVolumeRbacTest, self).tearDown()

    def _create_volume(self):
        # create_volume waits for volume status to be
        # "available" before returning and automatically
        # cleans up at the end of testing
        volume = self.create_volume()
        return volume

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:create")
    @decorators.idempotent_id('426b08ef-6394-4d06-9128-965d5a6c38ef')
    def test_create_volume(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        # Create a volume
        self._create_volume()

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:delete")
    @decorators.idempotent_id('6de9f9c2-509f-4558-867b-af21c7163be4')
    def test_delete_volume(self):
        try:
            # Create a volume
            volume = self._create_volume()
            rbac_utils.switch_role(self, switchToRbacRole=True)
            # Delete a volume
            self.volumes_client.delete_volume(volume['id'])
        except exceptions.NotFound as e:
            raise rbac_exceptions.RbacActionFailed(e)


class CreateDeleteVolumeV3RbacTest(CreateDeleteVolumeRbacTest):
    _api_version = 3
