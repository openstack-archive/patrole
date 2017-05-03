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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class SecurityGroupsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    # Tests in this class will fail with a 404 from microversion 2.36,
    # according to:
    # https://developer.openstack.org/api-ref/compute/#security-groups-os-security-groups-deprecated
    max_microversion = '2.35'

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-security-groups")
    @decorators.idempotent_id('4ac58e49-48c1-4fca-a6c3-3f95fb99eb77')
    def test_list_security_groups(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.security_groups_client.list_security_groups()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-security-groups")
    @decorators.idempotent_id('e8fe7f5a-69ee-412d-81d3-a8c7a488b54d')
    def test_create_security_groups(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_security_group()['id']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-security-groups")
    @decorators.idempotent_id('59127e8e-302d-11e7-93ae-92361f002671')
    def test_delete_security_groups(self):
        sec_group_id = self.create_security_group()['id']
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.security_groups_client.delete_security_group(sec_group_id)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-security-groups")
    @decorators.idempotent_id('3de5c6bc-b822-469e-a627-82427d38b067')
    def test_update_security_groups(self):
        sec_group_id = self.create_security_group()['id']
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        new_name = data_utils.rand_name()
        new_desc = data_utils.rand_name()
        self.security_groups_client.update_security_group(sec_group_id,
                                                          name=new_name,
                                                          description=new_desc)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-security-groups")
    @decorators.idempotent_id('6edc0320-302d-11e7-93ae-92361f002671')
    def test_show_security_groups(self):
        sec_group_id = self.create_security_group()['id']
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.security_groups_client.show_security_group(sec_group_id)
