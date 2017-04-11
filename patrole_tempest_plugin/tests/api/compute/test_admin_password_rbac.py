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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


CONF = config.CONF


class AdminPasswordRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AdminPasswordRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.change_password:
            raise cls.skipException('Change password not available.')

    @classmethod
    def setup_clients(cls):
        super(AdminPasswordRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def resource_setup(cls):
        super(AdminPasswordRbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-admin-password")
    @decorators.idempotent_id('908a7d59-3a66-441c-94cf-38e57ed14956')
    def test_change_server_password(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.change_password(
            self.server_id,
            adminPass=data_utils.rand_password())
