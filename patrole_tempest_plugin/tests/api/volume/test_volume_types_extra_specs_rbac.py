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
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeTypesExtraSpecsRbacTest(rbac_base.BaseVolumeRbacTest):

    def _create_volume_type(self, name=None, **kwargs):
        """Create a test volume-type"""
        name = name or data_utils.rand_name(
            self.__class__.__name__ + '-volume-type')
        volume_type = self.volume_types_client.create_volume_type(
            name=name, **kwargs)['volume_type']
        self.addCleanup(self.volume_types_client.delete_volume_type,
                        volume_type['id'])
        return volume_type

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume_extension:types_extra_specs")
    @decorators.idempotent_id('eea40251-990b-49b0-99ae-10e4585b479b')
    def test_create_volume_type_extra_specs(self):
        vol_type = self._create_volume_type()
        # List Volume types extra specs.
        extra_specs = {"spec1": "val1"}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volume_types_client.create_volume_type_extra_specs(
            vol_type['id'], extra_specs)
