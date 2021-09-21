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

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF

if CONF.policy_feature_enabled.changed_cinder_policies_xena:
    _TYPE_MANAGE_CREATE = "volume_extension:type_create"
    _TYPE_MANAGE_UPDATE = "volume_extension:type_update"
    _TYPE_MANAGE_DELETE = "volume_extension:type_delete"
else:
    _TYPE_MANAGE_CREATE = "volume_extension:types_manage"
    _TYPE_MANAGE_UPDATE = "volume_extension:types_manage"
    _TYPE_MANAGE_DELETE = "volume_extension:types_manage"


class VolumeTypesRbacTest(rbac_base.BaseVolumeRbacTest):

    @decorators.idempotent_id('e2bbf968-d947-4a15-a4da-a98c3069731e')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_TYPE_MANAGE_CREATE])
    def test_create_volume_type(self):
        with self.override_role():
            self.create_volume_type()

    @decorators.idempotent_id('2b74ac82-e03e-4801-86f3-d05c9acfd66b')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_TYPE_MANAGE_UPDATE])
    def test_update_volume_type(self):
        volume_type = self.create_volume_type()
        with self.override_role():
            self.volume_types_client.update_volume_type(
                volume_type['id'], description='updated-description')

    @decorators.idempotent_id('90aec0ef-4f9b-4170-be6b-a392c12540be')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_TYPE_MANAGE_DELETE])
    def test_delete_volume_type(self):
        volume_type = self.create_volume_type()
        with self.override_role():
            self.volume_types_client.delete_volume_type(volume_type['id'])
        self.volume_types_client.wait_for_resource_deletion(volume_type['id'])
