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

from oslo_serialization import base64
from oslo_serialization import jsonutils as json

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesBackupsRbacTest(rbac_base.BaseVolumeRbacTest):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(VolumesBackupsRbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.backup:
            raise cls.skipException("Cinder backup feature disabled")

    @classmethod
    def setup_clients(cls):
        super(VolumesBackupsRbacTest, cls).setup_clients()
        cls.admin_backups_client = cls.os_admin.backups_v2_client

    @classmethod
    def resource_setup(cls):
        super(VolumesBackupsRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _decode_url(self, backup_url):
        return json.loads(base64.decode_as_text(backup_url))

    def _encode_backup(self, backup):
        retval = json.dumps(backup)
        return base64.encode_as_text(retval)

    def _modify_backup_url(self, backup_url, changes):
        backup = self._decode_url(backup_url)
        backup.update(changes)
        return self._encode_backup(backup)

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:create")
    @decorators.idempotent_id('6887ec94-0bcf-4ab7-b30f-3808a4b5a2a5')
    def test_create_backup(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_backup(volume_id=self.volume['id'])

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:get")
    @decorators.idempotent_id('abd92bdd-b0fb-4dc4-9cfc-de9e968f8c8a')
    def test_show_backup(self):
        backup = self.create_backup(volume_id=self.volume['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.backups_client.show_backup(backup['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:get_all")
    @decorators.idempotent_id('4d18f0f0-7e01-4007-b622-dedc859b22f6')
    def test_list_backups(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.backups_client.list_backups()

    @decorators.idempotent_id('dbd69865-876f-4835-b70e-7341153fb162')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:get_all")
    def test_list_backups_with_details(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.backups_client.list_backups(detail=True)

    @decorators.attr(type='slow')
    @decorators.idempotent_id('50f43bde-205e-438e-9a05-5eac07fc3d63')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:backup_admin_actions:reset_status")
    def test_reset_backup_status(self):
        backup = self.create_backup(volume_id=self.volume['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.backups_client.reset_backup_status(backup_id=backup['id'],
                                                status='error')
        waiters.wait_for_volume_resource_status(self.admin_backups_client,
                                                backup['id'], 'error')

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:restore")
    @decorators.idempotent_id('9c794bf9-2446-4f41-8fe0-80b71e757f9d')
    def test_restore_backup(self):
        backup = self.create_backup(volume_id=self.volume['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        restore = self.backups_client.restore_backup(backup['id'])['restore']
        waiters.wait_for_volume_resource_status(
            self.admin_backups_client, restore['backup_id'], 'available')

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:delete")
    @decorators.idempotent_id('d5d0c6a2-413d-437e-a73f-4bf2b41a20ed')
    def test_delete_backup(self):
        # Do not call the create_backup in Tempest's base volume class, because
        # it doesn't use ``test_utils.call_and_ignore_notfound_exc`` for clean
        # up.
        backup = self.backups_client.create_backup(
            volume_id=self.volume['id'])['backup']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.backups_client.delete_backup, backup['id'])
        waiters.wait_for_volume_resource_status(self.admin_backups_client,
                                                backup['id'], 'available')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.backups_client.delete_backup(backup['id'])
        # Wait for deletion so error isn't thrown during clean up.
        self.admin_backups_client.wait_for_resource_deletion(backup['id'])

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:export-import")
    @decorators.idempotent_id('e984ec8d-e8eb-485c-98bc-f1856020303c')
    def test_export_backup(self):
        backup = self.create_backup(volume_id=self.volume['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.backups_client.export_backup(backup['id'])['backup-record']

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:backup-import")
    @decorators.idempotent_id('1e70f039-4556-44cc-9cc1-edf2b7ed648b')
    def test_import_backup(self):
        backup = self.create_backup(volume_id=self.volume['id'])
        export_backup = self.backups_client.export_backup(
            backup['id'])['backup-record']
        new_id = data_utils.rand_uuid()
        new_url = self._modify_backup_url(
            export_backup['backup_url'], {'id': new_id})

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        import_backup = self.backups_client.import_backup(
            backup_service=export_backup['backup_service'],
            backup_url=new_url)['backup']
        self.addCleanup(self.backups_client.delete_backup, import_backup['id'])


class VolumesBackupsV3RbacTest(VolumesBackupsRbacTest):
    _api_version = 3


class VolumesBackupsV318RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    # The minimum microversion for showing 'os-backup-project-attr:project_id'
    # is 3.18.
    min_microversion = '3.18'
    max_microversion = 'latest'

    @classmethod
    def skip_checks(cls):
        super(VolumesBackupsV318RbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.backup:
            raise cls.skipException("Cinder backup feature disabled")

    @decorators.idempotent_id('69801485-d5be-4e75-bbb4-168d50b5a8c2')
    @rbac_rule_validation.action(service="cinder",
                                 rule="backup:backup_project_attribute")
    def test_show_backup_project_attribute(self):
        volume = self.create_volume()
        backup = self.create_backup(volume_id=volume['id'])
        expected_attr = 'os-backup-project-attr:project_id'

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.backups_client.show_backup(backup['id'])['backup']

        # Show backup API attempts to inject the attribute below into the
        # response body but only if policy enforcement succeeds.
        if expected_attr not in body:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)
