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

import testtools

from tempest.common import compute
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesActionsRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(VolumesActionsRbacTest, cls).setup_clients()
        cls.client = cls.os.volumes_client

    @classmethod
    def resource_setup(cls):
        super(VolumesActionsRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _create_server(self):
        body, _ = compute.create_test_server(self.os, wait_until='ACTIVE')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.servers_client.delete_server, body['id'])
        return body

    def _attach_volume(self, server):
        self.servers_client.attach_volume(
            server['id'], volumeId=self.volume['id'],
            device='/dev/%s' % CONF.compute.volume_device_name)
        waiters.wait_for_volume_resource_status(
            self.client, self.volume['id'], 'in-use')
        self.addCleanup(self._detach_volume)

    def _detach_volume(self):
        self.client.detach_volume(self.volume['id'])
        waiters.wait_for_volume_resource_status(
            self.client, self.volume['id'], 'available')

    @testtools.skipUnless(CONF.service_available.nova,
                          "Nova is required to create a server")
    @rbac_rule_validation.action(service="cinder", rule="volume:attach")
    @decorators.idempotent_id('f97b10e4-2eed-4f8b-8632-71c02cb9fe42')
    def test_attach_volume_to_instance(self):
        server = self._create_server()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Attach the volume
        self._attach_volume(server)

    @test.attr(type="slow")
    @rbac_rule_validation.action(service="cinder", rule="volume:detach")
    @decorators.idempotent_id('5a042f6a-688b-42e6-a02e-fe5c47b89b07')
    def test_detach_volume_from_instance(self):
        # Attach the volume
        server = self._create_server()
        self._attach_volume(server)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Detach the volume
        self._detach_volume()

    @testtools.skipIf(True, "Patrole bug #1672799")
    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:copy_volume_to_image")
    @decorators.idempotent_id('b0d0da46-903c-4445-893e-20e680d68b50')
    def test_volume_upload(self):
        self.image_client = self.os.image_client
        image_name = data_utils.rand_name('image')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.client.upload_volume(
            self.volume['id'], image_name=image_name,
            disk_format=CONF.volume.disk_format)['os-volume_upload_image']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.image_client.delete_image,
                        body['image_id'])
        waiters.wait_for_volume_resource_status(
            self.client, self.volume['id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_readonly_flag")
    @decorators.idempotent_id('2750717a-f250-4e41-9e09-02624aad6ff8')
    def test_volume_readonly_update(self):
        volume = self.create_volume()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Update volume readonly
        self.client.update_volume_readonly(volume['id'], readonly=True)

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_admin_actions:reset_status")
    @decorators.idempotent_id('4b3dad7d-0e73-4839-8781-796dd3d7af1d')
    def test_volume_reset_status(self):
        volume = self.create_volume()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.reset_volume_status(volume['id'], status='error')

    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_admin_actions:force_delete")
    @decorators.idempotent_id('a312a937-6abf-4b91-a950-747086cbce48')
    def test_volume_force_delete(self):
        volume = self.create_volume()
        self.client.reset_volume_status(volume['id'], status='error')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.force_delete_volume(volume['id'])
        self.client.wait_for_resource_deletion(volume['id'])


class VolumesActionsV3RbacTest(VolumesActionsRbacTest):
    _api_version = 3
