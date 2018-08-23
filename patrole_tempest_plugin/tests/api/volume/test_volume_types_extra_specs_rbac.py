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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeTypesExtraSpecsRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(VolumeTypesExtraSpecsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-types-extra-specs', 'volume'):
            msg = "os-types-extra-specs extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(VolumeTypesExtraSpecsRbacTest, cls).resource_setup()
        cls.vol_type = cls.create_volume_type()
        cls.spec_key = data_utils.rand_name(cls.__name__ + '-Spec')

    def _create_volume_type_extra_specs(self, ignore_not_found=False):
        extra_specs = {self.spec_key: "val1"}
        self.volume_types_client.create_volume_type_extra_specs(
            self.vol_type['id'], extra_specs)

        if ignore_not_found:
            self.addCleanup(
                test_utils.call_and_ignore_notfound_exc,
                self.volume_types_client.delete_volume_type_extra_specs,
                self.vol_type['id'], self.spec_key)
        else:
            self.addCleanup(
                self.volume_types_client.delete_volume_type_extra_specs,
                self.vol_type['id'], self.spec_key)

    @decorators.idempotent_id('76c36be2-2b6c-4acf-9aac-c9dc5c17cdbe')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:types_extra_specs:index"])
    def test_list_volume_types_extra_specs(self):
        with self.rbac_utils.override_role(self):
            self.volume_types_client.list_volume_types_extra_specs(
                self.vol_type['id'])['extra_specs']

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:types_extra_specs:create"])
    @decorators.idempotent_id('eea40251-990b-49b0-99ae-10e4585b479b')
    def test_create_volume_type_extra_specs(self):
        with self.rbac_utils.override_role(self):
            self._create_volume_type_extra_specs(ignore_not_found=True)

    @decorators.idempotent_id('e2dcc9c6-2fef-431d-afaf-92b45bc76d1a')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:types_extra_specs:show"])
    def test_show_volume_type_extra_specs(self):
        self._create_volume_type_extra_specs()

        with self.rbac_utils.override_role(self):
            self.volume_types_client.show_volume_type_extra_specs(
                self.vol_type['id'], self.spec_key)

    @decorators.idempotent_id('93001912-f938-41c7-8787-62dc7010fd52')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:types_extra_specs:delete"])
    def test_delete_volume_type_extra_specs(self):
        self._create_volume_type_extra_specs(ignore_not_found=True)

        with self.rbac_utils.override_role(self):
            self.volume_types_client.delete_volume_type_extra_specs(
                self.vol_type['id'], self.spec_key)

    @decorators.idempotent_id('0a444437-7402-4fbe-a18a-93af2ee00618')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:types_extra_specs:update"])
    def test_update_volume_type_extra_specs(self):
        self._create_volume_type_extra_specs()
        update_extra_specs = {self.spec_key: "val2"}

        with self.rbac_utils.override_role(self):
            self.volume_types_client.update_volume_type_extra_specs(
                self.vol_type['id'], self.spec_key, update_extra_specs)
