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
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ServerVolumeAttachmentRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ServerVolumeAttachmentRbacTest, cls).setup_clients()
        cls.volumes_client = cls.os_primary.volumes_client_latest

    @classmethod
    def skip_checks(cls):
        super(ServerVolumeAttachmentRbacTest, cls).skip_checks()
        if not CONF.service_available.cinder:
            skip_msg = ("%s skipped as Cinder is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def resource_setup(cls):
        super(ServerVolumeAttachmentRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')
        cls.volume = cls.create_volume()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:index")
    @decorators.idempotent_id('529b668b-6edb-41d5-8886-d7dbd0614678')
    def test_list_volume_attachments(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_volume_attachments(self.server['id'])[
            'volumeAttachments']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:create")
    @decorators.idempotent_id('21c2c3fd-fbe8-41b1-8ef8-115ec47d54c1')
    def test_create_volume_attachment(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.attach_volume(self.server, self.volume)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:show")
    @decorators.idempotent_id('997df9c2-6e54-47b6-ab74-e4fdb500f385')
    def test_show_volume_attachment(self):
        attachment = self.attach_volume(self.server, self.volume)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_volume_attachment(
            self.server['id'], attachment['id'])

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:update")
    @decorators.idempotent_id('bd667186-eca6-4b78-ab6a-3e2fabcb971f')
    def test_update_volume_attachment(self):
        attachment = self.attach_volume(self.server, self.volume)
        alt_volume = self.create_volume()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.update_attached_volume(
            self.server['id'], attachment['id'], volumeId=alt_volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                alt_volume['id'], 'in-use')
        # On teardown detach the volume and wait for it to be available. This
        # is so we don't error out when trying to delete the volume during
        # teardown.
        self.addCleanup(waiters.wait_for_volume_resource_status,
                        self.volumes_client, alt_volume['id'], 'available')
        # Ignore 404s on detach in case the server is deleted or the volume
        # is already detached.
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.servers_client.detach_volume,
                        self.server['id'], alt_volume['id'])

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes-attachments:delete")
    @decorators.idempotent_id('12b03e90-d087-46af-9c4d-507d021c4984')
    def test_delete_volume_attachment(self):
        self.attach_volume(self.server, self.volume)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.detach_volume(self.server['id'], self.volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                self.volume['id'], 'available')
