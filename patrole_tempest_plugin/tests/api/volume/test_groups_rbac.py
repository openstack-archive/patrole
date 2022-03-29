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
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF

if CONF.policy_feature_enabled.changed_cinder_policies_xena:
    _GROUP_CREATE = "group:group_types:create"
    _GROUP_UPDATE = "group:group_types:update"
    _GROUP_DELETE = "group:group_types:delete"
else:
    _GROUP_CREATE = "group:group_types_manage"
    _GROUP_UPDATE = "group:group_types_manage"
    _GROUP_DELETE = "group:group_types_manage"


class BaseGroupRbacTest(rbac_base.BaseVolumeRbacTest):

    def setUp(self):
        super(BaseGroupRbacTest, self).setUp()
        self.volume_type_id = self.create_volume_type()['id']
        self.group_type_id = self.create_group_type()['id']

    def _create_group(self, name=None, ignore_notfound=False, **kwargs):
        group_name = name or data_utils.rand_name(
            self.__class__.__name__ + '-Group')
        group = self.groups_client.create_group(name=group_name, **kwargs)[
            'group']
        if ignore_notfound:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self._delete_group, group['id'])
        else:
            self.addCleanup(self._delete_group, group['id'])
        waiters.wait_for_volume_resource_status(
            self.groups_client, group['id'], 'available')
        return group

    def _delete_group(self, group_id):
        self.groups_client.delete_group(group_id, delete_volumes=True)
        self.groups_client.wait_for_resource_deletion(group_id)

        vols = self.volumes_client.list_volumes(
            detail=True, params={'all_tenants': True})['volumes']
        for vol in vols:
            if vol['group_id'] == group_id:
                self.volumes_client.wait_for_resource_deletion(
                    vol['id'])


class GroupsV3RbacTest(BaseGroupRbacTest):
    volume_min_microversion = '3.13'
    volume_max_microversion = 'latest'

    @decorators.idempotent_id('43235328-66ae-424f-bc7f-f709c0ca268c')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:create"])
    def test_create_group(self, name=None):

        group_name = name or data_utils.rand_name(
            self.__class__.__name__ + '-Group')
        with self.override_role():
            group = self.groups_client.create_group(
                name=group_name, group_type=self.group_type_id,
                volume_types=[self.volume_type_id])['group']
        self.addCleanup(self._delete_group, group['id'])

        waiters.wait_for_volume_resource_status(
            self.groups_client, group['id'], 'available')

    @decorators.idempotent_id('9dc34a62-ae3e-439e-92b6-9389ea4c2863')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:get"])
    def test_show_group(self):
        group = self._create_group(group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])

        with self.override_role():
            self.groups_client.show_group(group['id'])

    @decorators.idempotent_id('db43841b-a173-4317-acfc-f83e4e48e4ee')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:get_all"])
    def test_list_groups(self):
        with self.override_role():
            self.groups_client.list_groups()['groups']

    @decorators.idempotent_id('5378da93-9c26-4ad4-b039-0555e2b8f668')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:get_all"])
    def test_list_groups_with_details(self):
        with self.override_role():
            self.groups_client.list_groups(detail=True)['groups']

    @decorators.idempotent_id('f499fc48-df83-4917-bf8d-783ebf6f080b')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:update"])
    def test_update_group(self):
        group = self._create_group(group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])
        updated_name = data_utils.rand_name(self.__class__.__name__ + '-Group')

        with self.override_role():
            self.groups_client.update_group(group['id'], name=updated_name)

    @decorators.idempotent_id('66fda391-5774-42a9-a018-80b34e57ab76')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:delete"])
    def test_delete_group(self):

        group = self._create_group(ignore_notfound=True,
                                   group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])
        group_id = group['id']
        with self.override_role():
            self.groups_client.delete_group(group_id, delete_volumes=True)

        self.groups_client.wait_for_resource_deletion(group_id)
        vols = self.volumes_client.list_volumes(
            detail=True, params={'all_tenants': True})['volumes']
        for vol in vols:
            if vol['group_id'] == group_id:
                self.volumes_client.wait_for_resource_deletion(
                    vol['id'])


class GroupV320RbacTest(BaseGroupRbacTest):
    _api_version = 3
    volume_min_microversion = '3.20'
    volume_max_microversion = 'latest'

    @decorators.idempotent_id('b849c1d4-3215-4f9d-b1e6-0aeb4b2b65ac')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:reset_status"])
    def test_reset_group_status(self):
        group = self._create_group(ignore_notfound=False,
                                   group_type=self.group_type_id,
                                   volume_types=[self.volume_type_id])
        status = 'available'
        with self.override_role():
            self.groups_client.reset_group_status(group['id'],
                                                  status)
        waiters.wait_for_volume_resource_status(
            self.groups_client, group['id'], status)


class GroupTypesV3RbacTest(rbac_base.BaseVolumeRbacTest):
    volume_min_microversion = '3.11'
    volume_max_microversion = 'latest'

    @decorators.idempotent_id('2820f12c-4681-4c7f-b28d-e6925637dff6')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_GROUP_CREATE])
    def test_create_group_type(self):
        with self.override_role():
            self.create_group_type(ignore_notfound=True)

    @decorators.idempotent_id('f77f8156-4fc9-4f02-be15-8930f748e10c')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_GROUP_DELETE])
    def test_delete_group_type(self):
        group_type = self.create_group_type(ignore_notfound=True)

        with self.override_role():
            self.group_types_client.delete_group_type(group_type['id'])

    @decorators.idempotent_id('67929954-4551-4d22-b15a-27fb6e56b711')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_GROUP_DELETE])
    def test_update_group_type(self):
        group_type = self.create_group_type()
        update_params = {
            'name': data_utils.rand_name(
                self.__class__.__name__ + '-updated-group-type'),
            'description': 'updated-group-type-desc'
        }
        with self.override_role():
            self.group_types_client.update_group_type(
                group_type['id'], **update_params)

    @decorators.idempotent_id('a5f88c26-df7c-4f21-a3ae-7a4c2d6212b4')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:access_group_types_specs"])
    def test_create_group_type_group_specs(self):
        # TODO(felipemonteiro): Combine with ``test_create_group_type``
        # once multiple policy testing is supported. This policy is
        # only enforced after "group:group_types_manage".
        with self.override_role():
            group_type = self.create_group_type(ignore_notfound=True)

        if 'group_specs' not in group_type:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute='group_specs')

    @decorators.idempotent_id('8d9e2831-24c3-47b7-a76a-2e563287f12f')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:access_group_types_specs"])
    def test_show_group_type(self):
        group_type = self.create_group_type()
        with self.override_role():
            resp_body = self.group_types_client.show_group_type(
                group_type['id'])['group_type']
        if 'group_specs' not in resp_body:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute='group_specs')
