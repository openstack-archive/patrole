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

import time

from oslo_log import log as logging
import testtools

from tempest.common import waiters
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF
LOG = logging.getLogger(__name__)


# FIXME(felipemonteiro): `@decorators.attr(type='slow')` are added to tests
# below to in effect cause the tests to be non-voting in Zuul due to a high
# rate of spurious failures related to volume attachments. This will be
# revisited at a later date.
class ServerVolumeAttachmentRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources(network=True, subnet=True, router=True)
        super(ServerVolumeAttachmentRbacTest, cls).setup_credentials()

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

    def _detach_volume_and_wait_until_available(self, server, volume):
        self.servers_client.detach_volume(server['id'],
                                          volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')

    def _recreate_volume(self):
        try:
            # In case detachment failed, update the DB status of the volume
            # to avoid error getting thrown when deleting the volume.
            self.volumes_client.reset_volume_status(
                self.volume['id'], status='available',
                attach_status='detached')
            waiters.wait_for_volume_resource_status(
                self.volumes_client, self.volume['id'], 'available')
            # Next, forcibly delete the volume.
            self.volumes_client.force_delete_volume(self.volume['id'])
            self.volumes_client.wait_for_resource_deletion(self.volume['id'])
        except lib_exc.TimeoutException:
            LOG.exception('Failed to delete volume %s', self.volume['id'])
        # Finally, re-create the volume.
        self.__class__.volume = self.create_volume()

    def _restore_volume_status(self):
        # Forcibly detach any attachments still attached to the volume.
        try:
            attachments = self.volumes_client.show_volume(
                self.volume['id'])['volume']['attachments']
            if attachments:
                # Tests below only ever create one attachment for the volume.
                attachment = attachments[0]
                self.volumes_client.force_detach_volume(
                    self.volume['id'], connector=None,
                    attachment_id=attachment['id'])
                waiters.wait_for_volume_resource_status(self.volumes_client,
                                                        self.volume['id'],
                                                        'available')
        except lib_exc.TimeoutException:
            # If all else fails, rebuild the volume.
            self._recreate_volume()

    def setUp(self):
        super(ServerVolumeAttachmentRbacTest, self).setUp()
        self._restore_volume_status()

    def wait_for_server_volume_swap(self, server_id, old_volume_id,
                                    new_volume_id):
        """Waits for a server to swap the old volume to a new one."""
        volume_attachments = self.servers_client.list_volume_attachments(
            server_id)['volumeAttachments']
        attached_volume_ids = [attachment['volumeId']
                               for attachment in volume_attachments]
        start = int(time.time())

        while (old_volume_id in attached_volume_ids) \
                or (new_volume_id not in attached_volume_ids):
            time.sleep(self.servers_client.build_interval)
            volume_attachments = self.servers_client.list_volume_attachments(
                server_id)['volumeAttachments']
            attached_volume_ids = [attachment['volumeId']
                                   for attachment in volume_attachments]

            if int(time.time()) - start >= self.servers_client.build_timeout:
                old_vol_bdm_status = 'in BDM' \
                    if old_volume_id in attached_volume_ids else 'not in BDM'
                new_vol_bdm_status = 'in BDM' \
                    if new_volume_id in attached_volume_ids else 'not in BDM'
                message = ('Failed to swap old volume %(old_volume_id)s '
                           '(current %(old_vol_bdm_status)s) to new volume '
                           '%(new_volume_id)s (current %(new_vol_bdm_status)s)'
                           ' on server %(server_id)s within the required time '
                           '(%(timeout)s s)' %
                           {'old_volume_id': old_volume_id,
                            'old_vol_bdm_status': old_vol_bdm_status,
                            'new_volume_id': new_volume_id,
                            'new_vol_bdm_status': new_vol_bdm_status,
                            'server_id': server_id,
                            'timeout': self.servers_client.build_timeout})
                raise lib_exc.TimeoutException(message)

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-volumes-attachments:index"])
    @decorators.idempotent_id('529b668b-6edb-41d5-8886-d7dbd0614678')
    def test_list_volume_attachments(self):
        with self.override_role():
            self.servers_client.list_volume_attachments(self.server['id'])

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-volumes-attachments:create"])
    @decorators.idempotent_id('21c2c3fd-fbe8-41b1-8ef8-115ec47d54c1')
    def test_create_volume_attachment(self):
        with self.override_role():
            self.servers_client.attach_volume(self.server['id'],
                                              volumeId=self.volume['id'])
        # On teardown detach the volume and wait for it to be available. This
        # is so we don't error out when trying to delete the volume during
        # teardown.
        self.addCleanup(waiters.wait_for_volume_resource_status,
                        self.volumes_client, self.volume['id'], 'available')
        # Ignore 404s on detach in case the server is deleted or the volume
        # is already detached.
        self.addCleanup(self._detach_volume, self.server, self.volume)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                self.volume['id'], 'in-use')

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-volumes-attachments:show"])
    @decorators.idempotent_id('997df9c2-6e54-47b6-ab74-e4fdb500f385')
    def test_show_volume_attachment(self):
        attachment = self.attach_volume(self.server, self.volume)

        with self.override_role():
            self.servers_client.show_volume_attachment(
                self.server['id'], attachment['id'])

    @decorators.skip_because(bug='2008051', bug_type='storyboard')
    @decorators.attr(type='slow')
    @testtools.skipUnless(CONF.compute_feature_enabled.swap_volume,
                          'In-place swapping of volumes not supported.')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-volumes-attachments:update"])
    @decorators.idempotent_id('bd667186-eca6-4b78-ab6a-3e2fabcb971f')
    def test_update_volume_attachment(self):
        volume1 = self.volume
        volume2 = self.create_volume()
        # Attach "volume1" to server
        self.attach_volume(self.server, volume1)

        with self.override_role():
            # Swap volume from "volume1" to "volume2"
            self.servers_client.update_attached_volume(
                self.server['id'], volume1['id'], volumeId=volume2['id'])
        self.addCleanup(self._detach_volume_and_wait_until_available,
                        self.server, volume2)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume1['id'], 'available')
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume2['id'], 'in-use')
        self.wait_for_server_volume_swap(self.server['id'], volume1['id'],
                                         volume2['id'])

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-volumes-attachments:delete"])
    @decorators.idempotent_id('12b03e90-d087-46af-9c4d-507d021c4984')
    def test_delete_volume_attachment(self):
        self.attach_volume(self.server, self.volume)

        with self.override_role():
            self.servers_client.detach_volume(self.server['id'],
                                              self.volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                self.volume['id'], 'available')
