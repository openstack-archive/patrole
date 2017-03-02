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

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base as base

CONF = config.CONF


class ImagesMemberRbacTest(base.BaseV1ImageRbacTest):

    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def setup_clients(cls):
        super(ImagesMemberRbacTest, cls).setup_clients()
        cls.image_member_client = cls.os.image_member_client
        cls.alt_image_member_client = cls.os_alt.image_member_client

    @classmethod
    def resource_setup(cls):
        super(ImagesMemberRbacTest, cls).resource_setup()
        cls.alt_tenant_id = cls.alt_image_member_client.tenant_id

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(ImagesMemberRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="glance", rule="add_member")
    @decorators.idempotent_id('bda2bb78-e6ec-4b87-ba6d-1eaf1b28fa8b')
    def test_add_image_member(self):
        """Add image member

        RBAC test for the glance add_member policy
        """
        image = self.create_image()
        # Toggle role and add image member
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.create_image_member(image['id'],
                                                     self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance", rule="delete_member")
    @decorators.idempotent_id('9beaf28c-62b7-4c30-bbe5-4283aed1201c')
    def test_delete_image_member(self):
        """Delete image member

        RBAC test for the glance delete_member policy
        """
        image = self.create_image()
        self.image_member_client.create_image_member(image['id'],
                                                     self.alt_tenant_id)
        # Toggle role and delete image member
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.delete_image_member(image['id'],
                                                     self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance", rule="get_members")
    @decorators.idempotent_id('a0fcd855-31ef-458c-97e0-14a448cdd6da')
    def test_list_image_members(self):
        """List image members

        RBAC test for the glance get_members policy
        """
        image = self.create_image()
        self.image_member_client.create_image_member(image['id'],
                                                     self.alt_tenant_id)
        # Toggle role and delete image member
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.list_image_members(image['id'])
