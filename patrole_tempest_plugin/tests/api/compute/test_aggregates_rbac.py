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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class AggregatesRbacTest(rbac_base.BaseV2ComputeRbacTest):

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(AggregatesRbacTest, self).tearDown()

    @classmethod
    def skip_checks(cls):
        super(AggregatesRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(AggregatesRbacTest, cls).setup_clients()
        cls.hosts_client = cls.os.hosts_client

    def _create_aggregate(self):
        agg_name = data_utils.rand_name('aggregate')
        aggregate = self.aggregates_client.create_aggregate(name=agg_name)
        aggregate_id = aggregate['aggregate']['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.aggregates_client.delete_aggregate,
                        aggregate_id)
        return aggregate_id

    def _add_host_to_aggregate(self, aggregate_id):
        host_name = self.hosts_client.list_hosts()['hosts'][0]['host_name']
        self.aggregates_client.add_host(aggregate_id, host=host_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.aggregates_client.remove_host,
                        aggregate_id,
                        host=host_name)
        return host_name

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:create")
    @decorators.idempotent_id('ba754393-896e-434a-9704-452ff4a84f3f')
    def test_create_aggregate_rbac(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_aggregate()

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:show")
    @decorators.idempotent_id('8fb0b749-b120-4727-b3fb-bcfa3fa6f55b')
    def test_show_aggregate_rbac(self):
        aggregate_id = self._create_aggregate()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.aggregates_client.show_aggregate(aggregate_id)

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:index")
    @decorators.idempotent_id('146284da-5dd6-4c97-b598-42b480f014c6')
    def test_list_aggregate_rbac(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.aggregates_client.list_aggregates()['aggregates']

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:update")
    @decorators.idempotent_id('c94e0d69-99b6-477e-b301-2cd0e9d0ad81')
    def test_update_aggregate_rbac(self):
        aggregate_id = self._create_aggregate()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        new_name = data_utils.rand_name('aggregate')
        self.aggregates_client.update_aggregate(aggregate_id, name=new_name)

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:delete")
    @decorators.idempotent_id('5a50c5a6-0f12-4405-a1ce-2288ae895ea6')
    def test_delete_aggregate_rbac(self):
        aggregate_id = self._create_aggregate()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.aggregates_client.delete_aggregate(aggregate_id)

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:add_host")
    @decorators.idempotent_id('97e6e9df-5291-4faa-8147-755b2d1f1ce2')
    def test_add_host_to_aggregate_rbac(self):
        aggregate_id = self._create_aggregate()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._add_host_to_aggregate(aggregate_id)

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:remove_host")
    @decorators.idempotent_id('5b035a25-75d2-4d72-b4d6-0f0337335628')
    def test_remove_host_from_aggregate_rbac(self):
        aggregate_id = self._create_aggregate()
        host_name = self._add_host_to_aggregate(aggregate_id)
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.aggregates_client.remove_host(aggregate_id, host=host_name)

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-aggregates:set_metadata")
    @decorators.idempotent_id('ed6f3849-065c-4ae9-a81e-6ad7ed0d3d9d')
    def test_set_metadata_on_aggregate_rbac(self):
        aggregate_id = self._create_aggregate()
        rand_key = data_utils.rand_name('key')
        rand_val = data_utils.rand_name('val')
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.aggregates_client.set_metadata(
            aggregate_id,
            metadata={rand_key: rand_val})
