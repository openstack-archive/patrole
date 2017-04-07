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

from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class AgentsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AgentsRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-agents', 'compute'):
            raise cls.skipException(
                '%s skipped as os-agents not enabled' % cls.__name__)

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-agents")
    @decorators.idempotent_id('d1bc6d97-07f5-4f45-ac29-1c619a6a7e27')
    def test_list_agents_rbac(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.agents_client.list_agents()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-agents")
    @decorators.idempotent_id('77d6cae4-1ced-47f7-af2e-3d6a45958fd6')
    def test_create_agent(self):
        params = {'hypervisor': 'kvm', 'os': 'win', 'architecture': 'x86',
                  'version': '7.0', 'url': 'xxx://xxxx/xxx/xxx',
                  'md5hash': 'add6bb58e139be103324d04d82d8f545'}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.agents_client.create_agent(**params)['agent']
        self.addCleanup(self.agents_client.delete_agent,
                        body['agent_id'])
