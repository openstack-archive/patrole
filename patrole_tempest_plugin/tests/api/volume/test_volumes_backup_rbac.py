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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesBackupsRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(VolumesBackupsRbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.backup:
            raise cls.skipException("Cinder backup feature disabled")

    def create_backup(self, volume_id):
        backup_name = data_utils.rand_name(
            self.__class__.__name__ + '-backup')
        backup = self.backups_client.create_backup(
            volume_id=volume_id, name=backup_name)['backup']
        self.addCleanup(self.backups_client.delete_backup, backup['id'])
        waiters.wait_for_backup_status(self.backups_client, backup['id'],
                                       'available')
        return backup

    @classmethod
    def resource_setup(cls):
        super(VolumesBackupsRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _create_backup(self, volume_id):
        backup_name = data_utils.rand_name('backup')
        backup = self.backups_client.create_backup(
            volume_id=volume_id, name=backup_name)['backup']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.backups_client.delete_backup, backup['id'])
        waiters.wait_for_volume_resource_status(
            self.backups_client, backup['id'], 'available')
        return backup

    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:create")
    @decorators.idempotent_id('6887ec94-0bcf-4ab7-b30f-3808a4b5a2a5')
    def test_volume_backup_create(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_backup(volume_id=self.volume['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:get")
    @decorators.idempotent_id('abd92bdd-b0fb-4dc4-9cfc-de9e968f8c8a')
    def test_volume_backup_get(self):
        # Create a temp backup
        backup = self._create_backup(volume_id=self.volume['id'])
        # Get a given backup
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.backups_client.show_backup(backup['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:get_all")
    @decorators.idempotent_id('4d18f0f0-7e01-4007-b622-dedc859b22f6')
    def test_volume_backup_list(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.backups_client.list_backups()

    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:restore")
    @decorators.idempotent_id('9c794bf9-2446-4f41-8fe0-80b71e757f9d')
    def test_volume_backup_restore(self):
        # Create a temp backup
        backup = self._create_backup(volume_id=self.volume['id'])
        # Restore backup
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        restore = self.backups_client.restore_backup(backup['id'])['restore']
        waiters.wait_for_volume_resource_status(
            self.backups_client, restore['backup_id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:delete")
    @decorators.idempotent_id('d5d0c6a2-413d-437e-a73f-4bf2b41a20ed')
    def test_volume_backup_delete(self):
        # Create a temp backup
        backup = self._create_backup(volume_id=self.volume['id'])
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # Delete backup
        self.backups_client.delete_backup(backup['id'])


class VolumesBackupsV3RbacTest(VolumesBackupsRbacTest):
    _api_version = 3
