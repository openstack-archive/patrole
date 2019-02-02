# Copyright 2018 AT&T Corporation
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

from patrole_tempest_plugin.tests.api.volume import rbac_base
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation


class GroupTypeSpecsRbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    min_microversion = '3.11'
    max_microversion = 'latest'

    @decorators.idempotent_id('b2859734-00ad-4a22-88ee-541698e90d12')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:group_types_specs"]
    )
    def test_group_type_specs_create(self):
        # Create new group type
        group_type = self.create_group_type()

        # Create new group type specs
        create_specs = {
            "key1": "value1",
            "key2": "value2"
        }

        with self.override_role():
            self.group_types_client. \
                create_or_update_group_type_specs(
                    group_type['id'], create_specs)['group_specs']

    @decorators.idempotent_id('469d0253-aa13-423f-8264-231ac17effbf')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:group_types_specs"]
    )
    def test_group_type_specs_show(self):
        group_type = self.create_group_type()
        specs = {
            "key1": "value1",
            "key2": "value2"
        }
        self.group_types_client.create_or_update_group_type_specs(
            group_type['id'], specs)['group_specs']
        # Show specified item of group type specs
        with self.override_role():
            self.group_types_client.show_group_type_specs_item(
                group_type['id'], 'key2')

    @decorators.idempotent_id('2e706a4e-dec9-46bf-9426-1c5b6f3ce102')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:group_types_specs"]
    )
    def test_group_type_specs_update(self):
        group_type = self.create_group_type()
        # Update specified item of group type specs
        update_key = 'key3'
        update_spec = {update_key: "value3-updated"}
        self.group_types_client.create_or_update_group_type_specs(
            group_type['id'], update_spec)['group_specs']
        with self.override_role():
            self.group_types_client.update_group_type_specs_item(
                group_type['id'], update_key, update_spec)

    @decorators.idempotent_id('fd5e332b-fb2c-4957-ace9-11d60ddd5472')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:group_types_specs"]
    )
    def test_group_type_specs_list(self):
        group_type = self.create_group_type()
        with self.override_role():
            self.group_types_client.list_group_type_specs(
                group_type['id'])['group_specs']

    @decorators.idempotent_id('d9639a07-e441-4576-baf6-7ec732b16572')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["group:group_types_specs"]
    )
    def test_group_type_specs_delete(self):
        group_type = self.create_group_type()
        # Delete specified item of group type specs
        delete_key = 'key1'
        specs = {'key1': 'value1'}
        self.group_types_client.create_or_update_group_type_specs(
            group_type['id'], specs)['group_specs']
        with self.override_role():
            self.group_types_client.delete_group_type_specs_item(
                group_type['id'], delete_key)
