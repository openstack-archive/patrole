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

from tempest.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.orchestration import rbac_base


class TestRbacSoftwareConfig(rbac_base.BaseOrchestrationRbacTest):

    def setUp(self):
        super(TestRbacSoftwareConfig, self).setUp()
        self.config = self._config_create('a')
        self._deployment_create(self.config['id'])

    @rbac_rule_validation.action(service="heat",
                                 rule="software_configs:show")
    @decorators.idempotent_id('b2e7c98c-e17b-4f37-82f3-5d21eff86e79')
    def test_get_software_config(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_software_config(self.config['id'])

    @rbac_rule_validation.action(service="heat",
                                 rule="software_deployments:metadata")
    @decorators.idempotent_id('defa34ab-9d1f-4b14-8613-34e964c0c478')
    def test_get_deployment_metadata(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_software_deployment_metadata(self.server_id)

    @rbac_rule_validation.action(service="heat",
                                 rule="software_deployments:index")
    @decorators.idempotent_id('2a4dcb91-1803-4749-9cb7-5b69ba668b18')
    def test_get_deployment_list(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_software_deployments()

    @rbac_rule_validation.action(service="heat",
                                 rule="software_deployments:show")
    @decorators.idempotent_id('d4e627bc-88a3-4189-8092-151f22ed989d')
    def test_software_show_deployment(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_software_deployment(self.deployment_id)

    @rbac_rule_validation.action(service="heat",
                                 rule="software_deployments:update")
    @decorators.idempotent_id('90e8958c-6fa7-4515-b6d7-6d6952979f8c')
    def test_software_deployment_update(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        new_action = data_utils.rand_name('ACTION')
        new_status = data_utils.rand_name('STATUS')
        new_reason = data_utils.rand_name('REASON')
        self.client.update_software_deploy(self.deployment_id,
                                           self.server_id,
                                           self.config['id'],
                                           new_action, new_status,
                                           self.input_values,
                                           self.output_values,
                                           new_reason,
                                           self.signal_transport)

    @rbac_rule_validation.action(service="heat",
                                 rule="software_deployments:create")
    @decorators.idempotent_id('9175fe7b-4210-4c1d-acbb-954998a9fd77')
    def test_software_deployment_create(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._deployment_create(self.config['id'])

    @rbac_rule_validation.action(service="heat",
                                 rule="software_deployments:delete")
    @decorators.idempotent_id('20f4683d-7316-4d88-a6ea-1ee6013da908')
    def test_software_deployment_delete(self):
        deploy_id = self._deployment_create(self.config['id'])
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.delete_software_deploy(deploy_id)

    @rbac_rule_validation.action(service="heat",
                                 rule="software_configs:create")
    @decorators.idempotent_id('c8fb1c73-fcb6-46c2-9510-8ef0083c9620')
    def test_config_create(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._config_create('e')

    @rbac_rule_validation.action(service="heat",
                                 rule="software_configs:delete")
    @decorators.idempotent_id('f4f784ea-9878-4306-bc5f-041ba5307ce5')
    def test_config_delete(self):
        configuration = self._config_create('d')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.delete_software_config(configuration['id'])

    def _config_create(self, suffix):
        configuration = {'group': 'script',
                         'inputs': [],
                         'outputs': [],
                         'options': {}}
        configuration['name'] = 'heat_soft_config_%s' % suffix
        configuration['config'] = '#!/bin/bash echo init-%s' % suffix
        api_config = self.client.create_software_config(**configuration)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.client.delete_software_config,
            api_config['software_config']['id'])
        configuration['id'] = api_config['software_config']['id']
        return configuration

    def _deployment_create(self, config_id):
        self.server_id = data_utils.rand_name('dummy-server')
        self.action = 'ACTION_0'
        self.status = 'STATUS_0'
        self.input_values = {}
        self.output_values = []
        self.status_reason = 'REASON_0'
        self.signal_transport = 'NO_SIGNAL'
        self.deployment = self.client.create_software_deploy(
            self.server_id, config_id, self.action, self.status,
            self.input_values, self.output_values, self.status_reason,
            self.signal_transport)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.client.delete_software_deploy,
            self.deployment['software_deployment']['id'])
        self.deployment_id = self.deployment['software_deployment']['id']
        return self.deployment_id
