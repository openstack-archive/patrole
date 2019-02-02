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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class AgentsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AgentsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-agents', 'compute'):
            raise cls.skipException(
                '%s skipped as os-agents not enabled' % cls.__name__)

    def _param_helper(self, **kwargs):
        rand_key = 'architecture'
        if rand_key in kwargs:
            # NOTE: The rand_name is for avoiding agent conflicts.
            # If you try to create an agent with the same hypervisor,
            # os and architecture as an existing agent, Nova will return
            # an HTTPConflict or HTTPServerError.
            kwargs[rand_key] = data_utils.rand_name(kwargs[rand_key])
        return kwargs

    @rbac_rule_validation.action(
        service="nova", rules=["os_compute_api:os-agents"])
    @decorators.idempotent_id('d1bc6d97-07f5-4f45-ac29-1c619a6a7e27')
    def test_list_agents_rbac(self):
        with self.override_role():
            self.agents_client.list_agents()

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-agents"])
    @decorators.idempotent_id('77d6cae4-1ced-47f7-af2e-3d6a45958fd6')
    def test_create_agent(self):
        params = {'hypervisor': 'kvm', 'os': 'win', 'architecture': 'x86',
                  'version': '7.0', 'url': 'xxx://xxxx/xxx/xxx',
                  'md5hash': 'add6bb58e139be103324d04d82d8f545'}
        with self.override_role():
            body = self.agents_client.create_agent(**params)['agent']
        self.addCleanup(self.agents_client.delete_agent,
                        body['agent_id'])

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-agents"])
    @decorators.idempotent_id('b22f2681-9ffb-439b-b240-dae503e41020')
    def test_update_agent(self):
        params = self._param_helper(
            hypervisor='common', os='linux',
            architecture='x86_64', version='7.0',
            url='xxx://xxxx/xxx/xxx',
            md5hash='add6bb58e139be103324d04d82d8f545')
        body = self.agents_client.create_agent(**params)['agent']
        self.addCleanup(self.agents_client.delete_agent,
                        body['agent_id'])
        update_params = self._param_helper(
            version='8.0',
            url='xxx://xxxx/xxx/xxx2',
            md5hash='add6bb58e139be103324d04d82d8f547')

        with self.override_role():
            self.agents_client.update_agent(body['agent_id'], **update_params)

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-agents"])
    @decorators.idempotent_id('c5042af8-0682-43b0-abc4-bf33349e23dd')
    def test_delete_agent(self):
        params = self._param_helper(
            hypervisor='common', os='linux',
            architecture='x86_64', version='7.0',
            url='xxx://xxxx/xxx/xxx',
            md5hash='add6bb58e139be103324d04d82d8f545')
        body = self.agents_client.create_agent(**params)['agent']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.agents_client.delete_agent,
                        body['agent_id'])
        with self.override_role():
            self.agents_client.delete_agent(body['agent_id'])
