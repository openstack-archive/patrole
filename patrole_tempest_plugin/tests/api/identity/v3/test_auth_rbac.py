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
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityAuthV3RbacTest(rbac_base.BaseIdentityV3RbacTest):
    """Tests the APIs that enforce the auth policy actions.

    For more information about the auth policy actions, see:
    https://github.com/openstack/keystone/blob/master/keystone/common/policies/auth.py
    """

    # TODO(felipemonteiro): Add tests for identity:get_auth_catalog and
    # identity:get_auth_domains once the endpoints are implemented in Tempest's
    # identity v3 client.

    @classmethod
    def setup_clients(cls):
        super(IdentityAuthV3RbacTest, cls).setup_clients()
        cls.client = cls.identity_client

    @decorators.idempotent_id('2a9fbf7f-6feb-4161-ae4b-faf7d6421b1a')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_auth_projects")
    def test_list_auth_projects(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.list_auth_projects()['projects']
