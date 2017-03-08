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
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesBackupsAdminRbacTest(rbac_base.BaseVolumeAdminRbacTest):

    @classmethod
    def skip_checks(cls):
        super(VolumesBackupsAdminRbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.backup:
            raise cls.skipException("Cinder backup feature disabled")

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(VolumesBackupsAdminRbacTest, self).tearDown()

    @classmethod
    def resource_setup(cls):
        super(VolumesBackupsAdminRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    @test.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:backup-export")
    @decorators.idempotent_id('e984ec8d-e8eb-485c-98bc-f1856020303c')
    def test_volume_backup_export(self):
        # Create a temp backup
        backup = self.create_backup(volume_id=self.volume['id'])
        # Export Backup
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.backups_client.export_backup(
            backup['id'])['backup-record']

    @test.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:backup-import")
    @decorators.idempotent_id('1e70f039-4556-44cc-9cc1-edf2b7ed648b')
    def test_volume_backup_import(self):
        # Create a temp backup
        backup = self.create_backup(volume_id=self.volume['id'])
        # Export a temp backup
        export_backup = self.backups_client.export_backup(
            backup['id'])['backup-record']
        # Import the temp backup
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        import_backup = self.backups_client.import_backup(
            backup_service=export_backup['backup_service'],
            backup_url=export_backup['backup_url'])['backup']
        self.addCleanup(self.backups_client.delete_backup, import_backup['id'])


class VolumesBackupsAdminV3RbacTest(VolumesBackupsAdminRbacTest):
    _api_version = 3
