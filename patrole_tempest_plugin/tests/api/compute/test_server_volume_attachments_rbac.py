#    Copyright 2017 AT&T Corporation.
#    All Rights Reserved.
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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ServerVolumeAttachmentRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ServerVolumeAttachmentRbacTest, cls).setup_clients()
        cls.client = cls.servers_client
        cls.volumes_client = cls.os.volumes_client

    @classmethod
    def skip_checks(cls):
        super(ServerVolumeAttachmentRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    @classmethod
    def resource_setup(cls):
        super(ServerVolumeAttachmentRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    @classmethod
    def resource_cleanup(cls):
        test_utils.call_and_ignore_notfound_exc(cls.delete_server,
                                                cls.server['id'])
        super(ServerVolumeAttachmentRbacTest, cls).resource_cleanup()

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(ServerVolumeAttachmentRbacTest, self).tearDown()

    def _create_and_attach(self):
        self.volume = self.create_volume()
        self.attachment = self._attach(self.server, self.volume)

    def _attach(self, server, volume):
        attachment = self.client.attach_volume(
            server['id'],
            volumeId=volume['id'])['volumeAttachment']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._detach, server['id'], volume['id'])
        waiters.wait_for_volume_status(self.volumes_client, volume['id'],
                                       'in-use')
        return attachment

    def _detach(self, server_id, volume_id):
        # For test_update_volume_attachment, an addCleanup is called with
        # a stale volume, because a new volume is attached, so only detach
        # the new volume to avoid a bad request error.
        if hasattr(self, 'volume') and self.volume['id'] == volume_id:
            self.client.detach_volume(server_id, volume_id)
            waiters.wait_for_volume_status(self.volumes_client, volume_id,
                                           'available')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:index")
    @decorators.idempotent_id('529b668b-6edb-41d5-8886-d7dbd0614678')
    def test_list_volume_attachments(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_volume_attachments(self.server['id'])
        ['volumeAttachments']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:create")
    @decorators.idempotent_id('21c2c3fd-fbe8-41b1-8ef8-115ec47d54c1')
    def test_create_volume_attachment(self):
        self.volume = self.create_volume()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._attach(self.server, self.volume)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:show")
    @decorators.idempotent_id('997df9c2-6e54-47b6-ab74-e4fdb500f385')
    def test_show_volume_attachment(self):
        self._create_and_attach()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_volume_attachment(
            self.server['id'], self.attachment['id'])

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:update")
    @decorators.idempotent_id('bd667186-eca6-4b78-ab6a-3e2fabcb971f')
    def test_update_volume_attachment(self):
        self._create_and_attach()
        self.volume = self.create_volume()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.update_attached_volume(
            self.server['id'], self.attachment['id'],
            volumeId=self.volume['id'])
        self.addCleanup(self._detach, self.server['id'], self.volume['id'])
        waiters.wait_for_volume_status(self.volumes_client, self.volume['id'],
                                       'in-use')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:delete")
    @decorators.idempotent_id('12b03e90-d087-46af-9c4d-507d021c4984')
    def test_delete_volume_attachment(self):
        self._create_and_attach()
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self._detach(self.server['id'], self.volume['id'])
