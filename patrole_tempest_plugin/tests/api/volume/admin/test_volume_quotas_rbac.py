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

import logging

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

QUOTA_KEYS = ['gigabytes', 'snapshots', 'volumes']
QUOTA_USAGE_KEYS = ['reserved', 'limit', 'in_use']
CONF = config.CONF
LOG = logging.getLogger(__name__)


class VolumeQuotasAdminRbacTest(rbac_base.BaseVolumeAdminRbacTest):

    @classmethod
    def setup_credentials(cls):
        super(VolumeQuotasAdminRbacTest, cls).setup_credentials()
        cls.demo_tenant_id = cls.os.credentials.tenant_id

    @classmethod
    def setup_clients(cls):
        super(VolumeQuotasAdminRbacTest, cls).setup_clients()
        cls.client = cls.os.volume_quotas_client

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume_extension:quotas:show")
    @decorators.idempotent_id('b3c7177e-b6b1-4d0f-810a-fc95606964dd')
    def test_list_default_quotas(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_default_quota_set(
            self.demo_tenant_id)['quota_set']

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume_extension:quotas:update")
    @decorators.idempotent_id('60f8f421-1630-4953-b449-b22af32265c7')
    def test_update_all_quota_resources_for_tenant(self):
        new_quota_set = {'gigabytes': 1009,
                         'volumes': 11,
                         'snapshots': 11}
        # Update limits for all quota resources
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.update_quota_set(
            self.demo_tenant_id,
            **new_quota_set)['quota_set']


class VolumeQuotasAdminV3RbacTest(VolumeQuotasAdminRbacTest):
    _api_version = 3
