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

from tempest.common import image as common_image
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ImagesRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """RBAC tests for the Nova images API.

    These APIs are proxy calls to the Image service. Consequently, no Nova
    policy actions are enforced; instead, only Glance policy actions are
    enforced. As such, these tests check that only Glance policy actions are
    executed.
    """

    # These tests will fail with a 404 starting from microversion 2.36.
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#images-deprecated
    max_microversion = '2.35'

    @classmethod
    def skip_checks(cls):
        super(ImagesRbacTest, cls).skip_checks()
        if not CONF.service_available.glance:
            skip_msg = ("%s skipped as glance is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def setup_clients(cls):
        super(ImagesRbacTest, cls).setup_clients()
        if CONF.image_feature_enabled.api_v2:
            cls.glance_image_client = cls.os_primary.image_client_v2
        elif CONF.image_feature_enabled.api_v1:
            cls.glance_image_client = cls.os_primary.image_client
        else:
            raise lib_exc.InvalidConfiguration(
                'Either api_v1 or api_v2 must be True in '
                '[image-feature-enabled].')

    @classmethod
    def resource_setup(cls):
        super(ImagesRbacTest, cls).resource_setup()
        params = {'name': data_utils.rand_name(cls.__name__ + '-image')}
        if CONF.image_feature_enabled.api_v1:
            params = {'headers': common_image.image_meta_to_headers(**params)}

        cls.image = cls.glance_image_client.create_image(**params)
        cls.addClassResourceCleanup(
            cls.glance_image_client.wait_for_resource_deletion,
            cls.image['id'])
        cls.addClassResourceCleanup(
            cls.glance_image_client.delete_image, cls.image['id'])

    @decorators.idempotent_id('b861f302-b72b-4055-81db-c62ff30b136d')
    @rbac_rule_validation.action(
        service="glance",
        rules=["get_images"])
    def test_list_images(self):
        with self.rbac_utils.override_role(self):
            self.compute_images_client.list_images()

    @decorators.idempotent_id('4365ae0f-15ee-4b54-a527-1679faaed140')
    @rbac_rule_validation.action(
        service="glance",
        rules=["get_images"])
    def test_list_images_with_details(self):
        with self.rbac_utils.override_role(self):
            self.compute_images_client.list_images(detail=True)

    @decorators.idempotent_id('886dfcae-51bf-4610-9e52-82d7189524c2')
    @rbac_rule_validation.action(
        service="glance",
        rules=["get_image"])
    def test_show_image_details(self):
        with self.rbac_utils.override_role(self):
            self.compute_images_client.show_image(self.image['id'])

    @decorators.idempotent_id('5888c7aa-0803-46d4-a3fb-5d4729465cd5')
    @rbac_rule_validation.action(
        service="glance",
        rules=["delete_image"])
    def test_delete_image(self):
        image = self.glance_image_client.create_image(
            name=data_utils.rand_name(self.__class__.__name__ + '-image'))
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.glance_image_client.delete_image, image['id'])

        with self.rbac_utils.override_role(self):
            self.compute_images_client.delete_image(image['id'])


class ImagesMetadataRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """RBAC tests for the Nova metadata images API.

    These APIs are proxy calls to the Image service. Consequently, no Nova
    policy actions are enforced; instead, only Glance policy actions are
    enforced. As such, these tests check that only Glance policy actions are
    executed.
    """

    # These tests will fail with a 404 starting from microversion 2.39.
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#images-deprecated
    max_microversion = '2.38'

    @classmethod
    def skip_checks(cls):
        super(ImagesMetadataRbacTest, cls).skip_checks()
        if not CONF.service_available.glance:
            skip_msg = ("%s skipped as glance is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def setup_clients(cls):
        super(ImagesMetadataRbacTest, cls).setup_clients()
        if CONF.image_feature_enabled.api_v2:
            cls.glance_image_client = cls.os_primary.image_client_v2
        elif CONF.image_feature_enabled.api_v1:
            cls.glance_image_client = cls.os_primary.image_client
        else:
            raise lib_exc.InvalidConfiguration(
                'Either api_v1 or api_v2 must be True in '
                '[image-feature-enabled].')

    @classmethod
    def resource_setup(cls):
        super(ImagesMetadataRbacTest, cls).resource_setup()
        params = {'name': data_utils.rand_name(cls.__name__ + '-image')}
        if CONF.image_feature_enabled.api_v1:
            params = {'headers': common_image.image_meta_to_headers(**params)}

        cls.image = cls.glance_image_client.create_image(**params)
        cls.addClassResourceCleanup(
            cls.glance_image_client.wait_for_resource_deletion,
            cls.image['id'])
        cls.addClassResourceCleanup(
            cls.glance_image_client.delete_image, cls.image['id'])

    @decorators.idempotent_id('dbe09d4c-e615-48cb-b908-a06a0f410a8e')
    @rbac_rule_validation.action(
        service="glance",
        rules=["get_image"])
    def test_show_image_metadata_item(self):
        self.compute_images_client.set_image_metadata(self.image['id'],
                                                      meta={'foo': 'bar'})
        self.addCleanup(self.compute_images_client.delete_image_metadata_item,
                        self.image['id'], key='foo')

        with self.rbac_utils.override_role(self):
            self.compute_images_client.show_image_metadata_item(
                self.image['id'], key='foo')

    @decorators.idempotent_id('59f66079-d564-47e8-81b0-03c2e84d339e')
    @rbac_rule_validation.action(
        service="glance",
        rules=["get_image"])
    def test_list_image_metadata(self):
        with self.rbac_utils.override_role(self):
            self.compute_images_client.list_image_metadata(self.image['id'])

    @decorators.idempotent_id('575604aa-909f-4b1b-a5a5-cfae1f63044b')
    @rbac_rule_validation.action(
        service="glance",
        rules=["modify_image"])
    def test_create_image_metadata(self):
        with self.rbac_utils.override_role(self):
            # NOTE(felipemonteiro): Although the name of the client function
            # appears wrong, it's actually correct: update_image_metadata does
            # an http post.
            self.compute_images_client.update_image_metadata(
                self.image['id'], meta={'foo': 'bar'})
        self.addCleanup(self.compute_images_client.delete_image_metadata_item,
                        self.image['id'], key='foo')

    @decorators.idempotent_id('fb8c4eb6-00e5-454c-b8bc-0e801ec369f1')
    @rbac_rule_validation.action(
        service="glance",
        rules=["modify_image"])
    def test_update_image_metadata(self):
        with self.rbac_utils.override_role(self):
            self.compute_images_client.set_image_metadata(self.image['id'],
                                                          meta={'foo': 'bar'})
        self.addCleanup(self.compute_images_client.delete_image_metadata_item,
                        self.image['id'], key='foo')

    @decorators.idempotent_id('9c7c2036-af9b-49a8-8ba1-09b027ee5def')
    @rbac_rule_validation.action(
        service="glance",
        rules=["modify_image"])
    def test_update_image_metadata_item(self):
        with self.rbac_utils.override_role(self):
            self.compute_images_client.set_image_metadata_item(
                self.image['id'], meta={'foo': 'bar'}, key='foo')
        self.addCleanup(self.compute_images_client.delete_image_metadata_item,
                        self.image['id'], key='foo')

    @decorators.idempotent_id('5f0dc4e6-0761-4613-9bde-0a6acdc78f46')
    @rbac_rule_validation.action(
        service="glance",
        rules=["modify_image"])
    def test_delete_image_metadata_item(self):
        self.compute_images_client.set_image_metadata(self.image['id'],
                                                      meta={'foo': 'bar'})
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.compute_images_client.delete_image_metadata_item,
                        self.image['id'], key='foo')

        with self.rbac_utils.override_role(self):
            self.compute_images_client.delete_image_metadata_item(
                self.image['id'], key='foo')


class ImageSizeRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """Tests the ``image_size`` compute policies.

    NOTE(felipemonteiro): If Patrole is enhanced to test multiple policies
    simultaneously, these policy actions can be combined with the related
    tests from ``ImagesRbacTest`` above.
    """

    # These tests will fail with a 404 starting from microversion 2.36.
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#images-deprecated
    max_microversion = '2.35'

    @classmethod
    def skip_checks(cls):
        super(ImageSizeRbacTest, cls).skip_checks()
        if not CONF.service_available.glance:
            skip_msg = ("%s skipped as glance is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def setup_clients(cls):
        super(ImageSizeRbacTest, cls).setup_clients()
        if CONF.image_feature_enabled.api_v2:
            cls.glance_image_client = cls.os_primary.image_client_v2
        elif CONF.image_feature_enabled.api_v1:
            cls.glance_image_client = cls.os_primary.image_client
        else:
            raise lib_exc.InvalidConfiguration(
                'Either api_v1 or api_v2 must be True in '
                '[image-feature-enabled].')

    @classmethod
    def resource_setup(cls):
        super(ImageSizeRbacTest, cls).resource_setup()
        params = {'name': data_utils.rand_name(cls.__name__ + '-image')}
        if CONF.image_feature_enabled.api_v1:
            params = {'headers': common_image.image_meta_to_headers(**params)}

        cls.image = cls.glance_image_client.create_image(**params)
        cls.addClassResourceCleanup(
            cls.glance_image_client.wait_for_resource_deletion,
            cls.image['id'])
        cls.addClassResourceCleanup(
            cls.glance_image_client.delete_image, cls.image['id'])

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('fe34d2a6-5743-45bf-8f92-a1d703d7c7ab')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:image-size"])
    def test_show_image_includes_image_size(self):
        with self.rbac_utils.override_role(self):
            body = self.compute_images_client.show_image(self.image['id'])[
                'image']

        expected_attr = 'OS-EXT-IMG-SIZE:size'
        if expected_attr not in body:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('08342c7d-297d-42ee-b398-90fce2443792')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:image-size"])
    def test_list_images_with_details_includes_image_size(self):
        with self.rbac_utils.override_role(self):
            body = self.compute_images_client.list_images(detail=True)[
                'images']

        expected_attr = 'OS-EXT-IMG-SIZE:size'
        if expected_attr not in body[0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)
