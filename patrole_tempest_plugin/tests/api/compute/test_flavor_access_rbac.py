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

from oslo_config import cfg

from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = cfg.CONF


class FlavorAccessRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def resource_setup(cls):
        super(FlavorAccessRbacTest, cls).resource_setup()
        cls.flavor_id = cls.create_flavor(is_public=False)['id']
        cls.public_flavor_id = CONF.compute.flavor_ref
        cls.tenant_id = cls.os_primary.credentials.tenant_id

    @decorators.idempotent_id('a2bd3740-765d-4c95-ac98-9e027378c75e')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access")
    def test_show_flavor_contains_is_public_key(self):
        public_flavor_id = CONF.compute.flavor_ref

        with self.rbac_utils.override_role(self):
            body = self.flavors_client.show_flavor(public_flavor_id)[
                'flavor']

        expected_attr = 'os-flavor-access:is_public'
        if expected_attr not in body:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)

    @decorators.idempotent_id('dd388146-9750-4124-82ba-62deff1052bb')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access")
    def test_list_flavors_details_contains_is_public_key(self):
        expected_attr = 'os-flavor-access:is_public'

        with self.rbac_utils.override_role(self):
            flavors = self.flavors_client.list_flavors(detail=True)['flavors']
        # There should already be a public flavor available, namely
        # `CONF.compute.flavor_ref`.
        public_flavors = [f for f in flavors if expected_attr in f]

        # If the `expected_attr` was not found in any flavor, then policy
        # enforcement failed.
        if not public_flavors:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)

    @decorators.idempotent_id('39cb5c8f-9990-436f-9282-fc76a41d9bac')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access:add_tenant_access")
    def test_add_flavor_access(self):
        with self.rbac_utils.override_role(self):
            self.flavors_client.add_flavor_access(
                flavor_id=self.flavor_id, tenant_id=self.tenant_id)
        self.addCleanup(self.flavors_client.remove_flavor_access,
                        flavor_id=self.flavor_id, tenant_id=self.tenant_id)

    @decorators.idempotent_id('61b8621f-52e4-473a-8d07-e228af8853d1')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access:remove_tenant_access")
    def test_remove_flavor_access(self):
        self.flavors_client.add_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.flavors_client.remove_flavor_access,
                        flavor_id=self.flavor_id, tenant_id=self.tenant_id)

        with self.rbac_utils.override_role(self):
            self.flavors_client.remove_flavor_access(
                flavor_id=self.flavor_id, tenant_id=self.tenant_id)

    @decorators.idempotent_id('e1cf59fb-7f32-40a1-96b9-248ab23dd581')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access")
    def test_list_flavor_access(self):
        # Add flavor access for os_primary so that it can access the flavor or
        # else a NotFound is raised.
        self.flavors_client.add_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)
        self.addCleanup(self.flavors_client.remove_flavor_access,
                        flavor_id=self.flavor_id, tenant_id=self.tenant_id)

        with self.rbac_utils.override_role(self):
            self.flavors_client.list_flavor_access(self.flavor_id)
