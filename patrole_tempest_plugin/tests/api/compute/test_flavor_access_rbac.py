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

from oslo_log import log

from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class FlavorAccessAdminRbacTest(rbac_base.BaseV2ComputeAdminRbacTest):

    @classmethod
    def setup_clients(cls):
        super(FlavorAccessAdminRbacTest, cls).setup_clients()
        cls.client = cls.flavors_client

    @classmethod
    def skip_checks(cls):
        super(FlavorAccessAdminRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    @classmethod
    def resource_setup(cls):
        super(FlavorAccessAdminRbacTest, cls).resource_setup()
        cls.flavor_id = cls._create_flavor(is_public=False)['id']
        cls.tenant_id = cls.auth_provider.credentials.tenant_id

    @decorators.idempotent_id('a2bd3740-765d-4c95-ac98-9e027378c75e')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access")
    def test_list_flavor_access(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.client.list_flavor_access(self.flavor_id)
        except exceptions.NotFound as e:
            LOG.info("NotFound exception caught. Exception is thrown when "
                     "role doesn't have access to the endpoint."
                     "This is irregular and should be fixed.")
            raise rbac_exceptions.RbacActionFailed(e)

    @decorators.idempotent_id('39cb5c8f-9990-436f-9282-fc76a41d9bac')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-flavor-access:add_tenant_access")
    def test_add_flavor_access(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.add_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)
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
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.remove_flavor_access(
            flavor_id=self.flavor_id, tenant_id=self.tenant_id)
