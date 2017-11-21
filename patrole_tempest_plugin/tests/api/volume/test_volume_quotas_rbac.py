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

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeQuotasV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_credentials(cls):
        super(VolumeQuotasV3RbacTest, cls).setup_credentials()
        cls.demo_tenant_id = cls.os_primary.credentials.tenant_id

    @classmethod
    def setup_clients(cls):
        super(VolumeQuotasV3RbacTest, cls).setup_clients()
        cls.quotas_client = cls.os_primary.volume_quotas_v2_client

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume_extension:quotas:show")
    @decorators.idempotent_id('b3c7177e-b6b1-4d0f-810a-fc95606964dd')
    def test_list_default_quotas(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.quotas_client.show_default_quota_set(
            self.demo_tenant_id)['quota_set']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume_extension:quotas:update")
    @decorators.idempotent_id('60f8f421-1630-4953-b449-b22af32265c7')
    def test_update_all_quota_resources_for_tenant(self):
        new_quota_set = {'gigabytes': 1009,
                         'volumes': 11,
                         'snapshots': 11}
        # Update limits for all quota resources
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.quotas_client.update_quota_set(
            self.demo_tenant_id,
            **new_quota_set)['quota_set']
