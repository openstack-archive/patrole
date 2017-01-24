# Copyright 2017 AT&T Corporation
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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.compute import rbac_base
from tempest import config
from tempest.lib import decorators

CONF = config.CONF


class RBACAbsoluteLimitsTestJSON(rbac_base.BaseV2ComputeRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(RBACAbsoluteLimitsTestJSON, self).tearDown()

    @classmethod
    def setup_clients(cls):
        super(RBACAbsoluteLimitsTestJSON, cls).setup_clients()
        cls.identity_client = cls.os_adm.identity_client
        cls.tenants_client = cls.os_adm.tenants_client

    @classmethod
    def skip_checks(cls):
        super(RBACAbsoluteLimitsTestJSON, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    @rbac_rule_validation.action(service="nova",
                                 rule="os_compute_api:os-used-limits")
    @decorators.idempotent_id('3fb60f83-9a5f-4fdd-89d9-26c3710844a1')
    def test_used_limits_for_admin_rbac(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.limits_client.show_limits()
