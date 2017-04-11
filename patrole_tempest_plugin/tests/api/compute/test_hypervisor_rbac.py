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


class HypervisorRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(HypervisorRbacTest, cls).setup_clients()
        cls.client = cls.hypervisor_client

    @classmethod
    def skip_checks(cls):
        super(HypervisorRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-hypervisors', 'compute'):
            msg = "%s skipped as os-hypervisors extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)

    @decorators.idempotent_id('17bbeb9a-e73e-445f-a771-c794448ef562')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-hypervisors")
    def test_list_hypervisors(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_hypervisors()['hypervisors']
