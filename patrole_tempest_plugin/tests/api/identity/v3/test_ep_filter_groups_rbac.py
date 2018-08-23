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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class EndpointFilterGroupsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    interface = 'public'

    @classmethod
    def resource_setup(cls):
        super(EndpointFilterGroupsV3RbacTest, cls).resource_setup()
        cls.service_id = cls.setup_test_service()['id']

    def setUp(self):
        super(EndpointFilterGroupsV3RbacTest, self).setUp()
        self.endpoint_group_id = self._create_endpoint_group()

    def _create_endpoint_group(self, ignore_not_found=False):
        # Create an endpoint group
        ep_group_name = data_utils.rand_name(
            self.__class__.__name__ + '-EPFilterGroup')
        filters = {
            'filters': {
                'interface': self.interface,
                'service_id': self.service_id
            }
        }
        endpoint_group = self.endpoint_groups_client.create_endpoint_group(
            name=ep_group_name, **filters)['endpoint_group']

        if ignore_not_found:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.endpoint_groups_client.delete_endpoint_group,
                            endpoint_group['id'])
        else:
            self.addCleanup(self.endpoint_groups_client.delete_endpoint_group,
                            endpoint_group['id'])

        return endpoint_group['id']

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_endpoint_group"])
    @decorators.idempotent_id('b4765906-52ec-477b-b441-a8508ced68e3')
    def test_create_endpoint_group(self):
        with self.rbac_utils.override_role(self):
            self._create_endpoint_group(ignore_not_found=True)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_endpoint_groups"])
    @decorators.idempotent_id('089aa3a7-ba1f-4f70-a1cf-f298a845058a')
    def test_list_endpoint_groups(self):
        with self.rbac_utils.override_role(self):
            self.endpoint_groups_client.list_endpoint_groups()

    @decorators.idempotent_id('5c16368d-1485-4c28-9803-db3fa3510623')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:get_endpoint_group"])
    def test_check_endpoint_group(self):
        with self.rbac_utils.override_role(self):
            self.endpoint_groups_client.check_endpoint_group(
                self.endpoint_group_id)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:get_endpoint_group"])
    @decorators.idempotent_id('bd2b6fb8-661f-4255-84b2-50fea4a1dc61')
    def test_show_endpoint_group(self):
        with self.rbac_utils.override_role(self):
            self.endpoint_groups_client.show_endpoint_group(
                self.endpoint_group_id)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:update_endpoint_group"])
    @decorators.idempotent_id('028b9198-ec35-4bd5-8f72-e23dfb7a0c8e')
    def test_update_endpoint_group(self):
        updated_name = data_utils.rand_name(
            self.__class__.__name__ + '-EPFilterGroup')

        with self.rbac_utils.override_role(self):
            self.endpoint_groups_client.update_endpoint_group(
                self.endpoint_group_id, name=updated_name)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:delete_endpoint_group"])
    @decorators.idempotent_id('88cc105e-70d9-48ac-927e-200ef41e070c')
    def test_delete_endpoint_group(self):
        endpoint_group_id = self._create_endpoint_group(ignore_not_found=True)

        with self.rbac_utils.override_role(self):
            self.endpoint_groups_client.delete_endpoint_group(
                endpoint_group_id)
