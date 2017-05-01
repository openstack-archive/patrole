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

from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class SimpleTenantUsageRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(SimpleTenantUsageRbacTest, cls).setup_clients()
        cls.client = cls.os_primary.tenant_usages_client

    @classmethod
    def skip_checks(cls):
        super(SimpleTenantUsageRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-simple-tenant-usage', 'compute'):
            msg = ("%s skipped as os-simple-tenant-usage not "
                   "enabled." % cls.__name__)
            raise cls.skipException(msg)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-simple-tenant-usage:list")
    @decorators.idempotent_id('2aef094f-0452-4df6-a66a-0ec22a92b16e')
    def test_simple_tenant_usage_list(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_tenant_usages()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-simple-tenant-usage:show")
    @decorators.idempotent_id('fe7eacda-15c4-4bf7-93ef-1091c4546a9d')
    def test_simple_tenant_usage_show(self):
        # A server must be created in order for usage activity to exist; else
        # the validation method in the API call throws an error.
        self.create_test_server(wait_until='ACTIVE')['id']
        tenant_id = self.auth_provider.credentials.tenant_id
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_tenant_usage(tenant_id=tenant_id)
