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

import six

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base


class BasicOperationsImagesRbacTest(rbac_base.BaseV2ImageRbacTest):

    @classmethod
    def setup_clients(cls):
        super(BasicOperationsImagesRbacTest, cls).setup_clients()
        cls.image_client = cls.os_primary.image_client_v2

    def _create_image(self, **kwargs):
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        image = self.create_image(name=image_name,
                                  container_format='bare',
                                  disk_format='raw',
                                  **kwargs)
        return image

    def _upload_image(self, image_id):
        image_file = six.BytesIO(data_utils.random_bytes())
        return self.image_client.store_image_file(image_id, image_file)

    @rbac_rule_validation.action(service="glance",
                                 rule="add_image")
    @decorators.idempotent_id('0f148510-63bf-11e6-b348-080027d0d606')
    def test_create_image(self):

        """Create Image Test

        RBAC test for the glance create_image endpoint
        """
        with self.rbac_utils.override_role(self):
            self._create_image()

    @rbac_rule_validation.action(service="glance",
                                 rule="upload_image")
    @decorators.idempotent_id('fdc0c7e2-ad58-4c5a-ba9d-1f6046a5b656')
    def test_upload_image(self):

        """Upload Image Test

        RBAC test for the glance upload_image endpoint
        """
        image = self._create_image()

        with self.rbac_utils.override_role(self):
            self._upload_image(image['id'])

    @decorators.idempotent_id('f0c268f3-cb51-49aa-9bd5-d30cf647322f')
    @rbac_rule_validation.action(service="glance",
                                 rule="download_image")
    def test_download_image(self):

        """Download Image Test

        RBAC test for the glance download_image endpoint
        """
        image = self._create_image()
        self._upload_image(image['id'])

        with self.rbac_utils.override_role(self):
            self.image_client.show_image_file(image['id'])

    @rbac_rule_validation.action(service="glance",
                                 rule="delete_image")
    @decorators.idempotent_id('3b5c341e-645b-11e6-ac4f-080027d0d606')
    def test_delete_image(self):

        """Delete created image

        RBAC test for the glance delete_image endpoint
        """
        image = self._create_image()

        with self.rbac_utils.override_role(self):
            self.image_client.delete_image(image['id'])
        self.image_client.wait_for_resource_deletion(image['id'])

    @rbac_rule_validation.action(service="glance",
                                 rule="get_image")
    @decorators.idempotent_id('3085c7c6-645b-11e6-ac4f-080027d0d606')
    def test_show_image(self):

        """Get created image

        RBAC test for the glance create_image endpoint
        """
        image = self._create_image()

        with self.rbac_utils.override_role(self):
            self.image_client.show_image(image['id'])

    @rbac_rule_validation.action(service="glance",
                                 rule="get_images")
    @decorators.idempotent_id('bf1a4e94-645b-11e6-ac4f-080027d0d606')
    def test_list_images(self):

        """List all the images

        RBAC test for the glance list_images endpoint
        """
        with self.rbac_utils.override_role(self):
            self.image_client.list_images()['images']

    @rbac_rule_validation.action(service="glance",
                                 rule="modify_image")
    @decorators.idempotent_id('32ecf48c-645e-11e6-ac4f-080027d0d606')
    def test_update_image(self):

        """Update given images

        RBAC test for the glance update_image endpoint
        """
        image = self._create_image()

        updated_image_name = data_utils.rand_name(
            self.__class__.__name__ + '-image')
        with self.rbac_utils.override_role(self):
            self.image_client.update_image(image['id'], [
                dict(replace='/name', value=updated_image_name)])

    @decorators.idempotent_id('244050d9-1b9a-446a-b3c5-f26f3ba8eb75')
    @rbac_rule_validation.action(service="glance",
                                 rule="modify_image")
    def test_create_image_tag(self):

        """Create image tag

        RBAC test for the glance add_image_tag endpoint
        """
        image = self._create_image()

        with self.rbac_utils.override_role(self):
            self.image_client.add_image_tag(
                image['id'],
                data_utils.rand_name(self.__class__.__name__ + '-tag'))

    @decorators.idempotent_id('c4a0bf9c-b78b-48c6-a31f-72c95f943c6e')
    @rbac_rule_validation.action(service="glance",
                                 rule="modify_image")
    def test_delete_image_tag(self):

        """Delete image tag

        RBAC test for the glance delete_image_tag endpoint
        """
        image = self._create_image()
        tag_name = data_utils.rand_name(self.__class__.__name__ + '-tag')
        self.image_client.add_image_tag(image['id'], tag_name)

        with self.rbac_utils.override_role(self):
            self.image_client.delete_image_tag(image['id'], tag_name)

    @rbac_rule_validation.action(service="glance",
                                 rule="publicize_image")
    @decorators.idempotent_id('0ea4809c-6461-11e6-ac4f-080027d0d606')
    def test_publicize_image(self):

        """Publicize Image Test

        RBAC test for the glance publicize_image endpoint
        """
        with self.rbac_utils.override_role(self):
            self._create_image(visibility='public')

    @decorators.idempotent_id('0f2d8427-134a-4d3c-a102-5fcdf5443d09')
    @rbac_rule_validation.action(service="glance",
                                 rule="communitize_image")
    def test_communitize_image(self):

        """Communitize Image Test

        RBAC test for the glance communitize_image policy
        """
        with self.rbac_utils.override_role(self):
            self._create_image(visibility='community')

    @rbac_rule_validation.action(service="glance",
                                 rule="deactivate")
    @decorators.idempotent_id('b488458c-65df-11e6-9947-080027824017')
    def test_deactivate_image(self):

        """Deactivate Image Test

        RBAC test for the glance deactivate_image endpoint
        """
        image = self._create_image()
        self._upload_image(image['id'])

        with self.rbac_utils.override_role(self):
            self.image_client.deactivate_image(image['id'])

    @rbac_rule_validation.action(service="glance",
                                 rule="reactivate")
    @decorators.idempotent_id('d3fa28b8-65df-11e6-9947-080027824017')
    def test_reactivate_image(self):

        """Reactivate Image Test

        RBAC test for the glance reactivate_image endpoint
        """
        image = self._create_image()
        self._upload_image(image['id'])

        with self.rbac_utils.override_role(self):
            self.image_client.reactivate_image(image['id'])
