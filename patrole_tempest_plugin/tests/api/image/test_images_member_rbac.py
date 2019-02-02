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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base as base


class ImagesMemberRbacTest(base.BaseV2ImageRbacTest):

    credentials = ['primary', 'alt']

    @classmethod
    def resource_setup(cls):
        super(ImagesMemberRbacTest, cls).resource_setup()
        cls.tenant_id = cls.image_member_client.tenant_id
        cls.alt_tenant_id = cls.os_alt.image_member_client_v2.tenant_id

    @classmethod
    def setup_clients(cls):
        super(ImagesMemberRbacTest, cls).setup_clients()
        cls.image_client = cls.os_primary.image_client_v2
        cls.image_member_client = cls.os_primary.image_member_client_v2

    @rbac_rule_validation.action(service="glance",
                                 rules=["add_member"])
    @decorators.idempotent_id('b1b85ace-6484-11e6-881e-080027d0d606')
    def test_add_image_member(self):

        """Add image member

        RBAC test for the glance add_member policy
        """
        image_id = self.create_image()['id']
        # Toggle role and add image member
        with self.override_role():
            self.image_member_client.create_image_member(
                image_id, member=self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance",
                                 rules=["delete_member"])
    @decorators.idempotent_id('ba075234-6484-11e6-881e-080027d0d606')
    def test_delete_image_member(self):

        """Delete image member

        RBAC test for the glance delete_member policy
        """
        image_id = self.create_image()['id']
        self.image_member_client.create_image_member(image_id,
                                                     member=self.alt_tenant_id)
        # Toggle role and delete image member
        with self.override_role():
            self.image_member_client.delete_image_member(image_id,
                                                         self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance",
                                 rules=["get_member"],
                                 expected_error_codes=[404])
    @decorators.idempotent_id('c01fd308-6484-11e6-881e-080027d0d606')
    def test_show_image_member(self):

        """Show image member

        RBAC test for the glance get_member policy
        """
        image_id = self.create_image()['id']
        self.image_member_client.create_image_member(
            image_id,
            member=self.alt_tenant_id)

        # Toggle role and get image member
        with self.override_role():
            self.image_member_client.show_image_member(image_id,
                                                       self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance",
                                 rules=["modify_member"])
    @decorators.idempotent_id('ca448bb2-6484-11e6-881e-080027d0d606')
    def test_update_image_member(self):

        """Update image member

        RBAC test for the glance modify_member policy
        """
        image_id = self.create_image(visibility='shared')['id']
        self.image_member_client.create_image_member(
            image_id,
            member=self.tenant_id)
        self.image_member_client.update_image_member(
            image_id, self.tenant_id,
            status='accepted')
        # Toggle role and update member
        with self.override_role():
            self.image_member_client.update_image_member(
                image_id, self.tenant_id,
                status='pending')

    @rbac_rule_validation.action(service="glance",
                                 rules=["get_members"])
    @decorators.idempotent_id('d0a2dc20-6484-11e6-881e-080027d0d606')
    def test_list_image_members(self):

        """List image member

        RBAC test for the glance get_members policy
        """
        image_id = self.create_image()['id']
        self.image_member_client.create_image_member(image_id,
                                                     member=self.alt_tenant_id)
        # Toggle role and list image members
        with self.override_role():
            self.image_member_client.list_image_members(image_id)
