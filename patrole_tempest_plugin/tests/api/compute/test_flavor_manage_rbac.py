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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class FlavorManageRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(FlavorManageRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('OS-FLV-EXT-DATA', 'compute'):
            msg = "OS-FLV-EXT-DATA extension not enabled."
            raise cls.skipException(msg)

    @decorators.idempotent_id('a4e7faec-7a4b-4809-9856-90d5b747ca35')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-flavor-manage:create"])
    def test_create_flavor_manage(self):
        with self.override_role():
            self.create_flavor()

    @decorators.idempotent_id('782e988e-061b-4c40-896f-a77c70c2b057')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-flavor-manage:delete"])
    def test_delete_flavor_manage(self):
        flavor_id = self.create_flavor()['id']

        with self.override_role():
            self.flavors_client.delete_flavor(flavor_id)
        self.flavors_client.wait_for_resource_deletion(flavor_id)
