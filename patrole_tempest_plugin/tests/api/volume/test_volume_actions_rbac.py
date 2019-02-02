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
from tempest.common import utils
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesActionsV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(VolumesActionsV3RbacTest, cls).setup_clients()
        cls.image_client = cls.os_primary.image_client_v2

    @classmethod
    def resource_setup(cls):
        super(VolumesActionsV3RbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _create_server(self):
        server, _ = compute.create_test_server(
            self.os_primary, wait_until='ACTIVE')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.servers_client.delete_server, server['id'])
        return server

    def _attach_volume(self, server, volume_id=None):
        if volume_id is None:
            volume_id = self.volume['id']

        self.servers_client.attach_volume(
            server['id'], volumeId=volume_id,
            device='/dev/%s' % CONF.compute.volume_device_name)
        waiters.wait_for_volume_resource_status(
            self.volumes_client, volume_id, 'in-use')
        self.addCleanup(self._detach_volume, volume_id)

    def _detach_volume(self, volume_id=None):
        if volume_id is None:
            volume_id = self.volume['id']

        self.volumes_client.detach_volume(volume_id)
        waiters.wait_for_volume_resource_status(
            self.volumes_client, volume_id, 'available')

    @testtools.skipUnless(
        CONF.policy_feature_enabled
        .volume_extension_volume_actions_attach_policy,
        '"volume_extension:volume_actions:attach" must be available in the '
        'cloud.')
    @utils.services('compute')
    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_actions:attach"])
    @decorators.idempotent_id('f97b10e4-2eed-4f8b-8632-71c02cb9fe42')
    def test_attach_volume_to_instance(self):
        server = self._create_server()
        volume_id = self.volume['id']

        with self.override_role():
            self.servers_client.attach_volume(
                server['id'], volumeId=volume_id,
                device='/dev/%s' % CONF.compute.volume_device_name)
        waiters.wait_for_volume_resource_status(
            self.volumes_client, volume_id, 'in-use')
        self.addCleanup(self._detach_volume, volume_id)

    @utils.services('compute')
    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_actions:detach"])
    @decorators.idempotent_id('5a042f6a-688b-42e6-a02e-fe5c47b89b07')
    def test_detach_volume_from_instance(self):
        server = self._create_server()
        self._attach_volume(server)
        volume_id = self.volume['id']

        with self.override_role():
            self.volumes_client.detach_volume(volume_id)
        waiters.wait_for_volume_resource_status(
            self.volumes_client, volume_id, 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:update_readonly_flag"])
    @decorators.idempotent_id('2750717a-f250-4e41-9e09-02624aad6ff8')
    def test_volume_readonly_update(self):
        with self.override_role():
            self.volumes_client.update_volume_readonly(self.volume['id'],
                                                       readonly=True)
        self.addCleanup(self.volumes_client.update_volume_readonly,
                        self.volume['id'], readonly=False)

    @decorators.idempotent_id('59b783c0-f4ef-430c-8a90-1bad97d4ec5c')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:update"])
    def test_volume_set_bootable(self):
        with self.override_role():
            self.volumes_client.set_bootable_volume(self.volume['id'],
                                                    bootable=True)

    @testtools.skipUnless(
        CONF.policy_feature_enabled
        .volume_extension_volume_actions_reserve_policy,
        '"volume_extension:volume_actions:reserve" must be available in the '
        'cloud.')
    @decorators.idempotent_id('41566922-75a1-4484-99c7-9c8782ee99ac')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_actions:reserve"])
    def test_volume_reserve(self):
        with self.override_role():
            self.volumes_client.reserve_volume(self.volume['id'])

    @testtools.skipUnless(
        CONF.policy_feature_enabled
        .volume_extension_volume_actions_unreserve_policy,
        '"volume_extension:volume_actions:unreserve" must be available in the '
        'cloud.')
    @decorators.idempotent_id('e5fa9564-77d9-4e57-b0c0-3e0ae4d08535')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_actions:unreserve"])
    def test_volume_unreserve(self):
        with self.override_role():
            self.volumes_client.unreserve_volume(self.volume['id'])

    @decorators.idempotent_id('c015c82f-7010-48cc-bd71-4ef542046f20')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:retype"])
    def test_volume_retype(self):
        vol_type = self.create_volume_type()['name']
        volume = self.create_volume()

        with self.override_role():
            self.volumes_client.retype_volume(volume['id'], new_type=vol_type)
        waiters.wait_for_volume_retype(
            self.volumes_client, volume['id'], vol_type)

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_admin_actions:reset_status"])
    @decorators.idempotent_id('4b3dad7d-0e73-4839-8781-796dd3d7af1d')
    def test_volume_reset_status(self):
        volume = self.create_volume()

        with self.override_role():
            self.volumes_client.reset_volume_status(
                volume['id'], status='error')

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_admin_actions:force_delete"])
    @decorators.idempotent_id('a312a937-6abf-4b91-a950-747086cbce48')
    def test_volume_force_delete(self):
        volume = self.create_volume()
        self.volumes_client.reset_volume_status(volume['id'], status='error')

        with self.override_role():
            self.volumes_client.force_delete_volume(volume['id'])
        self.volumes_client.wait_for_resource_deletion(volume['id'])

    @decorators.idempotent_id('48bd302b-950a-4830-840c-3158246ecdcc')
    @utils.services('compute')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_admin_actions:force_detach"])
    def test_force_detach_volume_from_instance(self):
        volume = self.create_volume()
        server = self._create_server()
        self._attach_volume(server, volume['id'])
        attachment = self.volumes_client.show_volume(
            volume['id'])['volume']['attachments'][0]

        # Reset volume's status to error.
        self.volumes_client.reset_volume_status(volume['id'], status='error')

        with self.override_role():
            self.volumes_client.force_detach_volume(
                volume['id'], connector=None,
                attachment_id=attachment['attachment_id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')


class VolumesActionsV310RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    min_microversion = '3.10'
    max_microversion = 'latest'

    @classmethod
    def setup_clients(cls):
        super(VolumesActionsV310RbacTest, cls).setup_clients()
        cls.image_client = cls.os_primary.image_client_v2

    @classmethod
    def resource_setup(cls):
        super(VolumesActionsV310RbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    @decorators.attr(type=["slow"])
    @utils.services('image')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_actions:upload_image"])
    @decorators.idempotent_id('b0d0da46-903c-4445-893e-20e680d68b50')
    def test_volume_upload_image(self):
        # TODO(felipemonteiro): The ``upload_volume`` endpoint also enforces
        # "volume:copy_volume_to_image".
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')

        with self.override_role():
            body = self.volumes_client.upload_volume(
                self.volume['id'], image_name=image_name, visibility="private",
                disk_format=CONF.volume.disk_format)['os-volume_upload_image']
        image_id = body["image_id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.image_client.delete_image,
                        image_id)
        waiters.wait_for_image_status(self.image_client, image_id,
                                      'active')
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                self.volume['id'], 'available')

    @decorators.attr(type=["slow"])
    @utils.services('image')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:volume_actions:upload_public"])
    @decorators.idempotent_id('578a84dd-a6bd-4f97-a418-4a0c3c272c08')
    def test_volume_upload_public(self):
        # This also enforces "volume_extension:volume_actions:upload_image".
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')

        with self.override_role():
            body = self.volumes_client.upload_volume(
                self.volume['id'], image_name=image_name, visibility="public",
                disk_format=CONF.volume.disk_format)['os-volume_upload_image']
            image_id = body["image_id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.image_client.delete_image,
                        image_id)
        waiters.wait_for_image_status(self.image_client, image_id,
                                      'active')
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                self.volume['id'], 'available')


class VolumesActionsV312RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    min_microversion = '3.12'
    max_microversion = 'latest'

    @decorators.idempotent_id('a654833d-4811-4acd-93ef-5ac4a34c75bc')
    @rbac_rule_validation.action(service="cinder", rules=["volume:get_all"])
    def test_show_volume_summary(self):
        with self.override_role():
            self.volumes_client.show_volume_summary()
