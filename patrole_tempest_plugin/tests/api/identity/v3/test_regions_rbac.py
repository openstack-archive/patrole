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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityRegionsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_region")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd119')
    def test_create_region(self):
        with self.rbac_utils.override_role(self):
            self.setup_test_region()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_region")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd120')
    def test_update_region(self):
        region = self.setup_test_region()
        new_description = data_utils.rand_name(
            self.__class__.__name__ + '-test_update_region')

        with self.rbac_utils.override_role(self):
            self.regions_client.update_region(region['id'],
                                              description=new_description)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_region")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd121')
    def test_delete_region(self):
        region = self.setup_test_region()

        with self.rbac_utils.override_role(self):
            self.regions_client.delete_region(region['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_region")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd122')
    def test_show_region(self):
        region = self.setup_test_region()

        with self.rbac_utils.override_role(self):
            self.regions_client.show_region(region['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_regions")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd123')
    def test_list_regions(self):
        with self.rbac_utils.override_role(self):
            self.regions_client.list_regions()
