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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class FlavorExtraSpecsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(FlavorExtraSpecsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-flavor-extra-specs', 'compute'):
            msg = "os-flavor-extra-specs extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(FlavorExtraSpecsRbacTest, cls).resource_setup()
        cls.flavor = cls.create_flavor()

    def _set_flavor_extra_spec(self):
        rand_key = data_utils.rand_name(self.__class__.__name__ + '-key')
        rand_val = data_utils.rand_name(self.__class__.__name__ + '-val')
        specs = {rand_key: rand_val}
        self.flavors_client.set_flavor_extra_spec(self.flavor['id'],
                                                  **specs)['extra_specs']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.flavors_client.unset_flavor_extra_spec,
                        self.flavor['id'], rand_key)
        return rand_key

    @decorators.idempotent_id('daee891d-dfe9-4501-a39c-29f2371bec3c')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-extra-specs:show")
    def test_show_flavor_extra_spec(self):
        key = self._set_flavor_extra_spec()
        with self.rbac_utils.override_role(self):
            self.flavors_client.show_flavor_extra_spec(self.flavor['id'], key)

    @decorators.idempotent_id('fcffeca2-ed04-4e85-bf93-02fb5643f22b')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-extra-specs:create")
    def test_set_flavor_extra_spec(self):
        with self.rbac_utils.override_role(self):
            self._set_flavor_extra_spec()

    @decorators.idempotent_id('42b85279-6bfa-4f58-b7a2-258c284f03c5')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-extra-specs:update")
    def test_update_flavor_extra_spec(self):
        key = self._set_flavor_extra_spec()
        update_val = data_utils.rand_name(self.__class__.__name__ + '-val')
        with self.rbac_utils.override_role(self):
            self.flavors_client.update_flavor_extra_spec(
                self.flavor['id'], key, **{key: update_val})

    @decorators.idempotent_id('4b0e5471-e010-4c09-8965-80898e6760a3')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-extra-specs:delete")
    def test_unset_flavor_extra_spec(self):
        key = self._set_flavor_extra_spec()
        with self.rbac_utils.override_role(self):
            self.flavors_client.unset_flavor_extra_spec(self.flavor['id'], key)

    @decorators.idempotent_id('02c3831a-3ce9-476e-a722-d805ac2da621')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-extra-specs:index")
    def test_list_flavor_extra_specs(self):
        self._set_flavor_extra_spec()
        with self.rbac_utils.override_role(self):
            self.flavors_client.list_flavor_extra_specs(self.flavor['id'])
