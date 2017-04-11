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
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = cfg.CONF


class FlavorAccessRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(FlavorAccessRbacTest, cls).setup_clients()
        cls.client = cls.flavors_client

    @classmethod
    def skip_checks(cls):
        super(FlavorAccessRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('OS-FLV-EXT-DATA', 'compute'):
            msg = "%s skipped as OS-FLV-EXT-DATA extension not enabled."\
                  % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(FlavorAccessRbacTest, cls).resource_setup()
        cls.flavor_id = cls._create_flavor(is_public=False)['id']
        cls.public_flavor_id = CONF.compute.flavor_ref
        cls.tenant_id = cls.auth_provider.credentials.tenant_id

    @decorators.idempotent_id('a2bd3740-765d-4c95-ac98-9e027378c75e')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access")
    def test_show_flavor(self):
        # NOTE(felipemonteiro): show_flavor enforces the specified policy
        # action, but only works if a public flavor is passed.
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_flavor(self.public_flavor_id)['flavor']

    @decorators.idempotent_id('39cb5c8f-9990-436f-9282-fc76a41d9bac')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access:add_tenant_access")
    def test_add_flavor_access(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.add_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)[
            'flavor_access']
        self.addCleanup(self.client.remove_flavor_access,
                        flavor_id=self.flavor_id, tenant_id=self.tenant_id)

    @decorators.idempotent_id('61b8621f-52e4-473a-8d07-e228af8853d1')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access:remove_tenant_access")
    def test_remove_flavor_access(self):
        self.client.add_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.client.remove_flavor_access,
                        flavor_id=self.flavor_id, tenant_id=self.tenant_id)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.remove_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)
