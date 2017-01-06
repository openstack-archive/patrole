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

import logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

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
    @test.idempotent_id('0f148510-63bf-11e6-b348-080027d0d606')
    def test_create_image(self):
        uuid = '00000000-1111-2222-3333-444455556666'
        image_name = data_utils.rand_name('image')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.create_image(name=image_name,
                          container_format='bare',
                          disk_format='raw',
                          visibility='private',
                          ramdisk_id=uuid)
