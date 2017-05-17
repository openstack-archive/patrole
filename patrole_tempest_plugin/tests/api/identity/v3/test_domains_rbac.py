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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityDomainsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_domain")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd110')
    def test_create_domain(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.setup_test_domain()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_domain")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd111')
    def test_update_domain(self):
        domain = self.setup_test_domain()
        new_domain_name = data_utils.rand_name(
            self.__class__.__name__ + '-test_update_domain')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.domains_client.update_domain(domain['id'],
                                          domain=domain,
                                          name=new_domain_name)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_domain")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd112')
    def test_delete_domain(self):
        domain = self.setup_test_domain()
        # A domain must be deactivated to be deleted
        self.domains_client.update_domain(domain['id'],
                                          domain=domain,
                                          enabled=False)
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.domains_client.delete_domain(domain['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd113')
    def test_show_domain(self):
        domain = self.setup_test_domain()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.domains_client.show_domain(domain['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_domains")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd114')
    def test_list_domains(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.domains_client.list_domains()
