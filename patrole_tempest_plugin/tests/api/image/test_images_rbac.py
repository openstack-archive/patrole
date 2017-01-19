# Copyright 2016 ATT Corporation.
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

from six import moves

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api import rbac_base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BasicOperationsImagesRbacTest(rbac_base.BaseV2ImageRbacTest):

    @classmethod
    def setup_clients(cls):
        super(BasicOperationsImagesRbacTest, cls).setup_clients()
        cls.client = cls.os.image_client_v2

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(BasicOperationsImagesRbacTest, self).tearDown()

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="add_image")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080027d0d606')
    def test_create_image(self):

        """Create Image Test

        RBAC test for the glance create_image endpoint
        """
        uuid = '00000000-1111-2222-3333-444455556666'
        image_name = data_utils.rand_name('image')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.create_image(name=image_name,
                          container_format='bare',
                          disk_format='raw',
                          visibility='private',
                          ramdisk_id=uuid)

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="upload_image")
    @decorators.idempotent_id('fdc0c7e2-ad58-4c5a-ba9d-1f6046a5b656')
    def test_upload_image(self):

        """Upload Image Test

        RBAC test for the glance upload_image endpoint
        """
        uuid = '00000000-1111-2222-3333-444455556666'
        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private',
                                 ramdisk_id=uuid)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        # Try uploading an image file
        image_file = moves.cStringIO(data_utils.random_bytes())
        self.client.store_image_file(body['id'], image_file)

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="delete_image")
    @decorators.idempotent_id('3b5c341e-645b-11e6-ac4f-080027d0d606')
    def test_delete_image(self):

        """Delete created image

        RBAC test for the glance delete_image endpoint
        """
        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='public')
        image_id = body.get('id')
        # Toggle role and delete created image
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.delete_image(image_id)
        self.client.wait_for_resource_deletion(image_id)

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="get_image")
    @decorators.idempotent_id('3085c7c6-645b-11e6-ac4f-080027d0d606')
    def test_show_image(self):

        """Get created image

        RBAC test for the glance create_image endpoint
        """

        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private')
        image_id = body.get('id')
        # Toggle role and get created image
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_image(image_id)

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="get_images")
    @decorators.idempotent_id('bf1a4e94-645b-11e6-ac4f-080027d0d606')
    def test_list_images(self):

        """List all the images

        RBAC test for the glance list_images endpoint
        """

        # Toggle role and get created image
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_images()

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="modify_image")
    @decorators.idempotent_id('32ecf48c-645e-11e6-ac4f-080027d0d606')
    def test_update_image(self):

        """Update given images

        RBAC test for the glance update_image endpoint
        """
        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private')
        image_id = body.get('id')

        # Now try uploading an image file
        image_file = moves.cStringIO(data_utils.random_bytes())
        self.client.store_image_file(image_id, image_file)

        # Toggle role and update created image
        rbac_utils.switch_role(self, switchToRbacRole=True)
        new_image_name = data_utils.rand_name('new-image')
        body = self.client.update_image(image_id, [
            dict(replace='/name', value=new_image_name)])

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="publicize_image")
    @decorators.idempotent_id('0ea4809c-6461-11e6-ac4f-080027d0d606')
    def test_publicize_image(self):

        """Publicize Image Test

        RBAC test for the glance publicize_image endpoint
        """
        image_name = data_utils.rand_name('image')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.create_image(name=image_name,
                          container_format='bare',
                          disk_format='raw',
                          visibility='public')

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="deactivate")
    @decorators.idempotent_id('b488458c-65df-11e6-9947-080027824017')
    def test_deactivate_image(self):

        """Deactivate Image Test

        RBAC test for the glance deactivate_image endpoint
        """
        uuid = '00000000-1111-2222-3333-444455556666'
        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private',
                                 ramdisk_id=uuid)
        image_id = body.get('id')
        # Now try uploading an image file
        image_file = moves.cStringIO(data_utils.random_bytes())
        self.client.store_image_file(image_id=image_id, data=image_file)
        # Toggling role and deacivate image
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.deactivate_image(image_id)

    @rbac_rule_validation.action(component="Image", service="glance",
                                 rule="reactivate")
    @decorators.idempotent_id('d3fa28b8-65df-11e6-9947-080027824017')
    def test_reactivate_image(self):

        """Reactivate Image Test

        RBAC test for the glance reactivate_image endpoint
        """
        uuid = '00000000-1111-2222-3333-444455556666'
        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private',
                                 ramdisk_id=uuid)

        # Now try uploading an image file
        image_id = body.get('id')
        image_file = moves.cStringIO(data_utils.random_bytes())
        self.client.store_image_file(image_id=image_id, data=image_file)
        # Toggling role and reactivate image
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.reactivate_image(image_id)
