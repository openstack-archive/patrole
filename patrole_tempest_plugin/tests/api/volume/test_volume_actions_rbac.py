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

    # TODO(felipemonteiro): "volume_extension:volume_actions:upload_public"
    # test can be created once volumes v3 client is created in Tempest.

    @classmethod
    def setup_clients(cls):
        super(VolumesActionsRbacTest, cls).setup_clients()
        cls.client = cls.volumes_client
        if CONF.image_feature_enabled.api_v1:
            cls.image_client = cls.os.image_client
        elif CONF.image_feature_enabled.api_v2:
            cls.image_client = cls.os.image_client_v2
        cls.image_id = CONF.compute.image_ref

    @classmethod
    def resource_setup(cls):
        super(VolumesActionsRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _create_server(self):
        server, _ = compute.create_test_server(self.os, wait_until='ACTIVE')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.servers_client.delete_server, server['id'])
        return server

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

    @test.services('compute')
    @rbac_rule_validation.action(service="cinder", rule="volume:attach")
    @decorators.idempotent_id('f97b10e4-2eed-4f8b-8632-71c02cb9fe42')
    def test_attach_volume_to_instance(self):
        server = self._create_server()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._attach_volume(server)

    @test.attr(type=["slow"])
    @test.services('compute')
    @rbac_rule_validation.action(service="cinder", rule="volume:detach")
    @decorators.idempotent_id('5a042f6a-688b-42e6-a02e-fe5c47b89b07')
    def test_detach_volume_from_instance(self):
        server = self._create_server()
        self._attach_volume(server)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._detach_volume()

    @test.services('image')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_actions:upload_image")
    @decorators.idempotent_id('b0d0da46-903c-4445-893e-20e680d68b50')
    def test_volume_upload(self):
        # TODO(felipemonteiro): The ``upload_volume`` endpoint also enforces
        # "volume:copy_volume_to_image" but is not currently contained in
        # Cinder's policy.json.
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.client.upload_volume(
            self.volume['id'], image_name=image_name, visibility="private",
            disk_format=CONF.volume.disk_format)['os-volume_upload_image']
        image_id = body["image_id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.image_client.delete_image,
                        image_id)
        waiters.wait_for_image_status(self.image_client, image_id, 'active')
        waiters.wait_for_volume_resource_status(self.os_adm.volumes_client,
                                                self.volume['id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:update_readonly_flag")
    @decorators.idempotent_id('2750717a-f250-4e41-9e09-02624aad6ff8')
    def test_volume_readonly_update(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        self.client.update_volume_readonly(self.volume['id'], readonly=True)
        self.addCleanup(self.client.update_volume_readonly,
                        self.volume['id'], readonly=False)

    @decorators.idempotent_id('a9d9e825-5ea3-42e6-96f3-7ac4e97b2ed0')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume:update_volume_metadata")
    def test_update_volume_image_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        self.volumes_client.update_volume_image_metadata(
            self.volume['id'], image_id=self.image_id)

    @decorators.idempotent_id('a41c8eed-2051-4a25-b401-df036faacbdc')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume:delete_volume_metadata")
    def test_delete_volume_image_metadata(self):
        self.volumes_client.update_volume_image_metadata(
            self.volume['id'], image_id=self.image_id)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.delete_volume_image_metadata(
            self.volume['id'], 'image_id')

    @decorators.idempotent_id('72bab13c-dfaf-4b6d-a132-c83a85fb1776')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_unmanage")
    def test_unmanage_volume(self):
        volume = self.create_volume()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_client.unmanage_volume(volume['id'])


class VolumesActionsV3RbacTest(VolumesActionsRbacTest):
    _api_version = 3
