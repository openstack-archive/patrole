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
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesManageV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(VolumesManageV3RbacTest, cls).skip_checks()

        if not CONF.volume_feature_enabled.manage_volume:
            raise cls.skipException("Manage volume tests are disabled")

        if len(CONF.volume.manage_volume_ref) != 2:
            raise cls.skipException("Manage volume ref is not correctly "
                                    "configured")

    @classmethod
    def setup_clients(cls):
        super(VolumesManageV3RbacTest, cls).setup_clients()
        cls.volume_manage_client = cls.os_primary.volume_manage_v2_client

    def _manage_volume(self, org_volume):
        # Manage volume
        new_volume_name = data_utils.rand_name(
            self.__class__.__name__ + '-volume')

        new_volume_ref = {
            'name': new_volume_name,
            'host': org_volume['os-vol-host-attr:host'],
            'ref': {CONF.volume.manage_volume_ref[0]:
                    CONF.volume.manage_volume_ref[1] % org_volume['id']},
            'volume_type': org_volume['volume_type'],
            'availability_zone': org_volume['availability_zone']}

        new_volume_id = self.volume_manage_client.manage_volume(
            **new_volume_ref)['volume']['id']

        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                new_volume_id, 'available')
        self.addCleanup(self.delete_volume,
                        self.volumes_client, new_volume_id)

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_manage"])
    @decorators.idempotent_id('114f9708-939b-407e-aeac-d21ebfabaad3')
    def test_volume_manage(self):
        volume_id = self.create_volume()['id']
        volume = self.volumes_client.show_volume(volume_id)['volume']

        # By default, the volume is managed after creation.  We need to
        # unmanage the volume first before testing manage volume.
        self.volumes_client.unmanage_volume(volume['id'])
        self.volumes_client.wait_for_resource_deletion(volume['id'])

        new_volume_name = data_utils.rand_name(
            self.__class__.__name__ + '-volume')

        new_volume_ref = {
            'name': new_volume_name,
            'host': volume['os-vol-host-attr:host'],
            'ref': {CONF.volume.manage_volume_ref[0]:
                    CONF.volume.manage_volume_ref[1] % volume['id']},
            'volume_type': volume['volume_type'],
            'availability_zone': volume['availability_zone']}

        with self.rbac_utils.override_role(self):
            try:
                new_volume_id = self.volume_manage_client.manage_volume(
                    **new_volume_ref)['volume']['id']
            except exceptions.Forbidden as e:
                # Since the test role under test does not have permission to
                # manage the volume, Forbidden exception is thrown and the
                # manageable list will not be cleaned up. Therefore, we need to
                # re-manage the volume at the end of the test case for proper
                # resource clean up.
                self.addCleanup(self._manage_volume, volume)
                raise exceptions.Forbidden(e)

        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                new_volume_id, 'available')
        self.addCleanup(
            self.delete_volume, self.volumes_client, new_volume_id)

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_unmanage"])
    @decorators.idempotent_id('d5d72abe-60bc-45ac-a8f2-c21b24f0b5d6')
    def test_volume_unmanage(self):
        volume_id = self.create_volume()['id']
        volume = self.volumes_client.show_volume(volume_id)['volume']

        with self.rbac_utils.override_role(self):
            self.volumes_client.unmanage_volume(volume['id'])
        self.volumes_client.wait_for_resource_deletion(volume['id'])

        # In order to clean up the manageable list, we need to re-manage the
        # volume after the test.  The _manage_volume method will set up the
        # proper resource cleanup
        self.addCleanup(self._manage_volume, volume)
