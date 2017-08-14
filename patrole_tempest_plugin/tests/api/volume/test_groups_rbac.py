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

from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class GroupsV3RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    min_microversion = '3.14'
    max_microversion = 'latest'

    def setUp(self):
        super(GroupsV3RbacTest, self).setUp()
        self.volume_type_id = self.create_volume_type()['id']
        self.group_type_id = self.create_group_type()['id']

    def _create_group(self, name=None, ignore_notfound=False, **kwargs):
        group_name = name or data_utils.rand_name(
            self.__class__.__name__ + '-Group')
        group = self.groups_client.create_group(name=group_name, **kwargs)[
            'group']
        waiters.wait_for_volume_resource_status(
            self.groups_client, group['id'], 'available')

        if ignore_notfound:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self._delete_group, group['id'])
        else:
            self.addCleanup(self._delete_group, group['id'])

        return group

    def _delete_group(self, group_id, delete_volumes=True):
        self.groups_client.delete_group(group_id, delete_volumes)
        self.groups_client.wait_for_resource_deletion(group_id)

    @decorators.idempotent_id('43235328-66ae-424f-bc7f-f709c0ca268c')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:create")
    def test_create_group(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_group(ignore_notfound=True,
                           group_type=self.group_type_id,
                           volume_types=[self.volume_type_id])

    @decorators.idempotent_id('9dc34a62-ae3e-439e-92b6-9389ea4c2863')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:get")
    def test_show_group(self):
        group = self._create_group(group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.groups_client.show_group(group['id'])

    @decorators.idempotent_id('db43841b-a173-4317-acfc-f83e4e48e4ee')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:get_all")
    def test_list_groups(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.groups_client.list_groups()['groups']

    @decorators.idempotent_id('5378da93-9c26-4ad4-b039-0555e2b8f668')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:get_all")
    def test_list_groups_with_details(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.groups_client.list_groups(detail=True)['groups']

    @decorators.idempotent_id('f499fc48-df83-4917-bf8d-783ebf6f080b')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:update")
    def test_update_group(self):
        group = self._create_group(group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])
        updated_name = data_utils.rand_name(self.__class__.__name__ + '-Group')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.groups_client.update_group(group['id'], name=updated_name)

    @decorators.idempotent_id('66fda391-5774-42a9-a018-80b34e57ab76')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:delete")
    def test_delete_group(self):
        group = self._create_group(ignore_notfound=True,
                                   group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.groups_client.delete_group(group['id'])


class GroupTypesV3RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    min_microversion = '3.11'
    max_microversion = 'latest'

    @decorators.idempotent_id('2820f12c-4681-4c7f-b28d-e6925637dff6')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:group_types_manage")
    def test_create_group_type(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.create_group_type(ignore_notfound=True)

    @decorators.idempotent_id('a5f88c26-df7c-4f21-a3ae-7a4c2d6212b4')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:access_group_types_specs")
    def test_create_group_type_group_specs(self):
        # TODO(felipemonteiro): Combine with ``test_create_group_type``
        # once multiple policy testing is supported. This policy is
        # only enforced after "group:group_types_manage".
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        group_type = self.create_group_type(ignore_notfound=True)

        if 'group_specs' not in group_type:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute='group_specs')

    @decorators.idempotent_id('f77f8156-4fc9-4f02-be15-8930f748e10c')
    @rbac_rule_validation.action(
        service="cinder",
        rule="group:group_types_manage")
    def test_delete_group_type(self):
        goup_type = self.create_group_type(ignore_notfound=True)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.group_types_client.delete_group_type(goup_type['id'])
