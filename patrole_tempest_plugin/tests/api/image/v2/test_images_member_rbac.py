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

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base as base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ImagesMemberRbacTest(base.BaseV2ImageRbacTest):

    credentials = ['admin', 'alt']

    @classmethod
    def resource_setup(cls):
        super(ImagesMemberRbacTest, cls).resource_setup()
        cls.alt_tenant_id = cls.alt_image_member_client.tenant_id

    @classmethod
    def setup_clients(cls):
        super(ImagesMemberRbacTest, cls).setup_clients()
        cls.image_client = cls.os.image_client_v2
        cls.alt_image_client = cls.os_alt.image_client_v2
        cls.image_member_client = cls.os.image_member_client_v2
        cls.alt_image_member_client = cls.os_alt.image_member_client_v2

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(ImagesMemberRbacTest, self).tearDown()

    def setUp(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(ImagesMemberRbacTest, self).setUp()

    @rbac_rule_validation.action(service="glance",
                                 rule="add_member")
    @decorators.idempotent_id('b1b85ace-6484-11e6-881e-080027d0d606')
    def test_add_image_member(self):

        """Add image member

        RBAC test for the glance add_member policy
        """
        image_id = self.create_image()['id']
        # Toggle role and add image member
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.create_image_member(image_id,
                                                     member=self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance",
                                 rule="delete_member")
    @decorators.idempotent_id('ba075234-6484-11e6-881e-080027d0d606')
    def test_delete_image_member(self):

        """Delete image member

        RBAC test for the glance delete_member policy
        """
        image_id = self.create_image()['id']
        self.image_member_client.create_image_member(image_id,
                                                     member=self.alt_tenant_id)
        # Toggle role and delete image member
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.delete_image_member(image_id,
                                                     self.alt_tenant_id)

    @rbac_rule_validation.action(service="glance",
                                 rule="get_member")
    @decorators.idempotent_id('c01fd308-6484-11e6-881e-080027d0d606')
    def test_show_image_member(self):

        """Show image member

        RBAC test for the glance get_member policy
        """
        try:
            image_id = self.create_image()['id']
            self.image_member_client.create_image_member(
                image_id,
                member=self.alt_tenant_id)

            # Toggle role and get image member
            self.rbac_utils.switch_role(self, switchToRbacRole=True)
            self.image_member_client.show_image_member(
                image_id,
                self.alt_tenant_id)
        except exceptions.NotFound as e:
            '''If the role doesn't have access to an image, a 404 exception is
            thrown when the roles tries to show an image member'''
            LOG.info("NotFound exception caught. Exception is thrown when "
                     "role doesn't have access to the image and tries to show "
                     "image members")
            raise rbac_exceptions.RbacActionFailed(e)

    @rbac_rule_validation.action(service="glance",
                                 rule="modify_member")
    @decorators.idempotent_id('ca448bb2-6484-11e6-881e-080027d0d606')
    def test_update_image_member(self):

        """Update image member

        RBAC test for the glance modify_member policy
        """
        image_id = self.create_image()['id']
        self.alt_image_member_client.create_image_member(
            image_id,
            member=self.image_client.tenant_id)
        # Toggle role and update member
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.update_image_member(
            image_id, self.image_client.tenant_id,
            status='accepted')

    @rbac_rule_validation.action(service="glance",
                                 rule="get_members")
    @decorators.idempotent_id('d0a2dc20-6484-11e6-881e-080027d0d606')
    def test_list_image_members(self):

        """List image member

        RBAC test for the glance get_members policy
        """
        image_id = self.create_image()['id']
        self.image_member_client.create_image_member(image_id,
                                                     member=self.alt_tenant_id)
        # Toggle role and list image members
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.image_member_client.list_image_members(image_id)
