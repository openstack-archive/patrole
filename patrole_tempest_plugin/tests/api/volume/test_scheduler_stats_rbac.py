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
from patrole_tempest_plugin.tests.api.volume import rbac_base


class SchedulerStatsRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(SchedulerStatsRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('scheduler-stats', 'volume'):
            msg = "%s skipped as scheduler-stats not enabled." % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(SchedulerStatsRbacTest, cls).setup_clients()
        cls.client = cls.os_primary.volume_scheduler_stats_v2_client

    @rbac_rule_validation.action(
        service="cinder",
        rule="scheduler_extension:scheduler_stats:get_pools")
    @decorators.idempotent_id('5f800441-4d30-48ec-9e5b-0d55bc86acbb')
    def test_list_back_end_storage_pools(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_pools()


class SchedulerStatsV3RbacTest(SchedulerStatsRbacTest):
    _api_version = 3
