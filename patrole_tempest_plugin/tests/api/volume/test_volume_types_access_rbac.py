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

from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeTypesAccessRbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3

    @classmethod
    def skip_checks(cls):
        super(VolumeTypesAccessRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-volume-type-access', 'volume'):
            msg = "os-volume-type-access extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(VolumeTypesAccessRbacTest, cls).resource_setup()
        cls.vol_type = cls.create_volume_type(
            **{'os-volume-type-access:is_public': False})
        cls.project_id = cls.os_primary.credentials.project_id

    def _add_type_access(self, ignore_not_found=False):
        self.volume_types_client.add_type_access(
            self.vol_type['id'], project=self.project_id)

        if ignore_not_found:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.volume_types_client.remove_type_access,
                            self.vol_type['id'], project=self.project_id)
        else:
            self.addCleanup(self.volume_types_client.remove_type_access,
                            self.vol_type['id'], project=self.project_id)

    @decorators.idempotent_id('af70e6ad-e931-419f-9200-8bcc284e4e47')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_type_access")
    def test_list_type_access(self):
        self._add_type_access()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volume_types_client.list_type_access(self.vol_type['id'])[
            'volume_type_access']

    @decorators.idempotent_id('b462eeba-45d0-4d6e-945a-a1d27708d367')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_type_access:addProjectAccess")
    def test_add_type_access(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._add_type_access(ignore_not_found=True)

    @decorators.idempotent_id('8f848aeb-636a-46f1-aeeb-e2a60e9d2bfe')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:volume_type_access:removeProjectAccess")
    def test_remove_type_access(self):
        self._add_type_access(ignore_not_found=True)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volume_types_client.remove_type_access(
            self.vol_type['id'], project=self.project_id)
