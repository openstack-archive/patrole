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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ImagesV235RbacTest(rbac_base.BaseV2ComputeRbacTest):
    """RBAC tests for the Nova images client.

    These APIs are proxy calls to the Image service. Consequently, no nova
    policy actions are enforced; instead, only glance policy actions are
    enforced. As such, these tests check that only glance policy actions are
    executed.
    """

    # These tests will fail with a 404 starting from microversion 2.36.
    min_microversion = '2.10'
    max_microversion = '2.35'

    @classmethod
    def skip_checks(cls):
        super(ImagesV235RbacTest, cls).skip_checks()
        if not CONF.service_available.glance:
            skip_msg = ("%s skipped as glance is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def setup_clients(cls):
        super(ImagesV235RbacTest, cls).setup_clients()
        cls.client = cls.compute_images_client
        cls.glance_image_client = cls.os_primary.image_client_v2

    @classmethod
    def resource_setup(cls):
        super(ImagesV235RbacTest, cls).resource_setup()
        cls.image = cls.glance_image_client.create_image(
            name=data_utils.rand_name('image'))

    @classmethod
    def resource_cleanup(cls):
        cls.glance_image_client.delete_image(cls.image['id'])
        super(ImagesV235RbacTest, cls).resource_cleanup()

    @decorators.idempotent_id('b861f302-b72b-4055-81db-c62ff30b136d')
    @rbac_rule_validation.action(
        service="glance",
        rule="get_images")
    def test_list_images(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_images()

    @decorators.idempotent_id('4365ae0f-15ee-4b54-a527-1679faaed140')
    @rbac_rule_validation.action(
        service="glance",
        rule="get_images")
    def test_list_images_with_details(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_images(detail=True)

    @decorators.idempotent_id('886dfcae-51bf-4610-9e52-82d7189524c2')
    @rbac_rule_validation.action(
        service="glance",
        rule="get_image")
    def test_show_image_details(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_image(self.image['id'])

    @decorators.idempotent_id('dbe09d4c-e615-48cb-b908-a06a0f410a8e')
    @rbac_rule_validation.action(
        service="glance",
        rule="get_image")
    def test_show_image_metadata_item(self):
        self.client.set_image_metadata(self.image['id'], meta={'foo': 'bar'})
        self.addCleanup(self.client.delete_image_metadata_item,
                        self.image['id'], key='foo')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_image_metadata_item(self.image['id'], key='foo')

    @decorators.idempotent_id('59f66079-d564-47e8-81b0-03c2e84d339e')
    @rbac_rule_validation.action(
        service="glance",
        rule="get_image")
    def test_list_image_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_image_metadata(self.image['id'])

    @decorators.idempotent_id('5888c7aa-0803-46d4-a3fb-5d4729465cd5')
    @rbac_rule_validation.action(
        service="glance",
        rule="delete_image")
    def test_delete_image(self):
        image = self.glance_image_client.create_image(
            name=data_utils.rand_name('image'))
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.glance_image_client.delete_image, image['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_image(image['id'])

    @decorators.idempotent_id('575604aa-909f-4b1b-a5a5-cfae1f63044b')
    @rbac_rule_validation.action(
        service="glance",
        rule="modify_image")
    def test_create_image_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # NOTE(felipemonteiro): Although the name of the client function
        # appears wrong, it's actually correct: update_image_metadata does an
        # http post.
        self.client.update_image_metadata(self.image['id'],
                                          meta={'foo': 'bar'})
        self.addCleanup(self.client.delete_image_metadata_item,
                        self.image['id'], key='foo')

    @decorators.idempotent_id('fb8c4eb6-00e5-454c-b8bc-0e801ec369f1')
    @rbac_rule_validation.action(
        service="glance",
        rule="modify_image")
    def test_update_image_metadata(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.set_image_metadata(self.image['id'], meta={'foo': 'bar'})
        self.addCleanup(self.client.delete_image_metadata_item,
                        self.image['id'], key='foo')

    @decorators.idempotent_id('9c7c2036-af9b-49a8-8ba1-09b027ee5def')
    @rbac_rule_validation.action(
        service="glance",
        rule="modify_image")
    def test_update_image_metadata_item(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.set_image_metadata_item(self.image['id'],
                                            meta={'foo': 'bar'}, key='foo')
        self.addCleanup(self.client.delete_image_metadata_item,
                        self.image['id'], key='foo')

    @decorators.idempotent_id('5f0dc4e6-0761-4613-9bde-0a6acdc78f46')
    @rbac_rule_validation.action(
        service="glance",
        rule="modify_image")
    def test_delete_image_metadata_item(self):
        self.client.set_image_metadata(self.image['id'], meta={'foo': 'bar'})
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.client.delete_image_metadata_item,
                        self.image['id'], key='foo')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_image_metadata_item(self.image['id'], key='foo')
