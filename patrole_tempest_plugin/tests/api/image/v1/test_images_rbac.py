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

import six

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base

CONF = config.CONF


class BasicOperationsImagesRbacTest(rbac_base.BaseV1ImageRbacTest):

    @rbac_rule_validation.action(service="glance", rule="add_image")
    @decorators.idempotent_id('33248a04-6527-11e6-be0f-080027d0d606')
    def test_create_image(self):
        """Create Image Test

        RBAC test for the glance add_image policy.
        """
        properties = {'prop1': 'val1'}
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_image(name=image_name,
                          container_format='bare',
                          disk_format='raw',
                          is_public=False,
                          properties=properties)

    @rbac_rule_validation.action(service="glance", rule="delete_image")
    @decorators.idempotent_id('731c8c81-6c63-413b-a61a-050ce9ca16ad')
    def test_delete_image(self):
        """Delete Image Test

        RBAC test for the glance delete_image policy.
        """
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        properties = {'prop1': 'val1'}
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 is_public=False,
                                 properties=properties)
        image_id = body['id']
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_image(image_id)

    @rbac_rule_validation.action(service="glance", rule="download_image")
    @decorators.idempotent_id('a22bf112-5a3a-419e-9cd6-9562d1a3a458')
    def test_download_image(self):
        """Download Image Test

        RBAC test for the glance download_image policy.
        """
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        properties = {'prop1': 'val1'}
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 is_public=False,
                                 properties=properties)
        image_id = body['id']
        # Now try uploading an image file
        image_file = six.BytesIO(data_utils.random_bytes())
        self.client.update_image(image_id, data=image_file)
        # Toggle role and get created image
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_image(image_id)

    @rbac_rule_validation.action(service="glance", rule="get_image")
    @decorators.idempotent_id('110257aa-6fa3-4cc0-b8dd-d93d43acd45c')
    def test_get_image(self):
        """Get Image Test

        RBAC test for the glance get_image policy.
        """
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        properties = {'prop1': 'val1'}
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 is_public=False,
                                 properties=properties)
        image_id = body['id']
        # Now try uploading an image file
        image_file = six.BytesIO(data_utils.random_bytes())
        self.client.update_image(image_id, data=image_file)
        # Toggle role and get created image
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.check_image(image_id)

    @rbac_rule_validation.action(service="glance", rule="get_images")
    @decorators.idempotent_id('37662238-0fe9-4dff-8d90-e02f31e7e3fb')
    def test_list_images(self):
        """Get Image Test

        RBAC test for the glance get_images policy.
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_images()

    @rbac_rule_validation.action(service="glance", rule="modify_image")
    @decorators.idempotent_id('3a391a19-d756-4c96-a346-72cc02f6106e')
    def test_update_image(self):
        """Update Image Test

        RBAC test for the glance modify_image policy.
        """
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        properties = {'prop1': 'val1'}
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 is_public=False,
                                 properties=properties)
        image_id = body.get('id')
        properties = {'prop1': 'val2'}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_image(image_id, headers=properties)

    @rbac_rule_validation.action(service="glance", rule="publicize_image")
    @decorators.idempotent_id('d5b1d09f-ba47-4d56-913e-4f38733a9a5c')
    def test_publicize_image(self):
        """Publicize Image Test

        RBAC test for the glance publicize_image policy.
        """
        image_name = data_utils.rand_name(self.__class__.__name__ + '-Image')
        properties = {'prop1': 'val1'}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_image(name=image_name,
                          container_format='bare',
                          disk_format='raw',
                          is_public=True,
                          properties=properties)
