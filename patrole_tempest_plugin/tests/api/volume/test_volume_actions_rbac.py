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


class VolumesActionsRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(VolumesActionsRbacTest, cls).skip_checks()
        # Nova is needed to create a server
        if not CONF.service_available.nova:
            skip_msg = ("%s skipped as nova is not available" % cls.__name__)
            raise cls.skipException(skip_msg)
        # Glance is needed to create an image
        if not CONF.service_available.glance:
            skip_msg = ("%s skipped as glance is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def setup_clients(cls):
        super(VolumesActionsRbacTest, cls).setup_clients()
        cls.client = cls.os.volumes_client
        cls.image_client = cls.os.image_client

    @classmethod
    def resource_setup(cls):
        super(VolumesActionsRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _attach_volume(self):
        server = self.create_server(wait_until='ACTIVE')
        self.servers_client.attach_volume(
            server['id'], volumeId=self.volume['id'],
            device='/dev/%s' % CONF.compute.volume_device_name)
        waiters.wait_for_volume_status(self.client,
                                       self.volume['id'], 'in-use')
        self.addCleanup(self._detach_volume)

    def _detach_volume(self):
        self.client.detach_volume(self.volume['id'])
        waiters.wait_for_volume_status(self.client, self.volume['id'],
                                       'available')

    @rbac_rule_validation.action(service="cinder", rule="volume:attach")
    @decorators.idempotent_id('f97b10e4-2eed-4f8b-8632-71c02cb9fe42')
    def test_attach_volume_to_instance(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # Attach the volume
        self._attach_volume()

    @rbac_rule_validation.action(service="cinder", rule="volume:detach")
    @decorators.idempotent_id('5a042f6a-688b-42e6-a02e-fe5c47b89b07')
    def test_detach_volume_to_instance(self):
        # Attach the volume
        self._attach_volume()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # Detach the volume
        self._detach_volume()

    @rbac_rule_validation.action(service="cinder", rule="volume:get")
    @decorators.idempotent_id('c4c3fdd5-b1b1-49c3-b977-a9f40ee9257a')
    def test_get_volume_attachment(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # Get attachment
        self.client.show_volume(self.volume['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:copy_volume_to_image")
    @decorators.idempotent_id('b0d0da46-903c-4445-893e-20e680d68b50')
    def test_volume_upload(self):
        image_name = data_utils.rand_name('image')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        body = self.client.upload_volume(
            self.volume['id'], image_name=image_name,
            disk_format=CONF.volume.disk_format)['os-volume_upload_image']
        image_id = body['image_id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.image_client.delete_image,
                        image_id)
        waiters.wait_for_image_status(self.image_client, image_id, 'active')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_readonly_flag")
    @decorators.idempotent_id('2750717a-f250-4e41-9e09-02624aad6ff8')
    def test_volume_readonly_update(self):
        volume = self.create_volume()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # Update volume readonly
        self.client.update_volume_readonly(volume['id'], readonly=True)


class VolumesActionsV3RbacTest(VolumesActionsRbacTest):
    _api_version = 3
