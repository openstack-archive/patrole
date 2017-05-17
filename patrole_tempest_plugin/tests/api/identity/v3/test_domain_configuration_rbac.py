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
from patrole_tempest_plugin.tests.api.identity import rbac_base

CONF = config.CONF


class DomainConfigurationV3RbacTest(rbac_base.BaseIdentityV3RbacTest):
    """RBAC tests for domain configuration client.

    Provides coverage for the following policy actions:
    https://github.com/openstack/keystone/blob/master/keystone/common/policies/domain_config.py
    """

    identity = {"driver": "ldap"}
    ldap = {"url": "ldap://myldap.com:389/",
            "user_tree_dn": "ou=Users,dc=my_new_root,dc=org"}

    @classmethod
    def setup_clients(cls):
        super(DomainConfigurationV3RbacTest, cls).setup_clients()
        cls.client = cls.domain_config_client

    @classmethod
    def resource_setup(cls):
        super(DomainConfigurationV3RbacTest, cls).resource_setup()
        cls.domain_id = cls.setup_test_domain()['id']

    def setUp(self):
        super(DomainConfigurationV3RbacTest, self).setUp()
        self._create_domain_config(self.domain_id)

    def _create_domain_config(self, domain_id):
        domain_config = self.client.create_domain_config(
            domain_id, identity=self.identity, ldap=self.ldap)['config']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.client.delete_domain_config,
                        domain_id)
        return domain_config

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_domain_config")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd115')
    def test_create_domain_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_domain_config(self.domain_id)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain_config")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd118')
    def test_show_domain_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_domain_config(self.domain_id)['config']

    @decorators.idempotent_id('1b539f95-4991-4e09-960f-fa771e1007d7')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain_config")
    def test_show_domain_group_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_domain_group_config(self.domain_id, 'identity')[
            'config']

    @decorators.idempotent_id('590c774d-a294-44f8-866e-aac9f4ab3809')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain_config")
    def test_show_domain_group_option_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_domain_group_option_config(self.domain_id, 'identity',
                                                    'driver')['config']

    @decorators.idempotent_id('21053885-1ce3-4167-b5e3-e470253481da')
    @rbac_rule_validation.action(
        service="keystone",
        rule="identity:get_security_compliance_domain_config")
    def test_show_security_compliance_domain_config(self):
        # The "security_compliance" group can only be shown for the default
        # domain.
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_domain_group_config(
            CONF.identity.default_domain_id, 'security_compliance')

    @decorators.idempotent_id('d1addd10-9ae4-4360-9961-47324fd22f23')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain_config_default")
    def test_show_default_config_settings(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_default_config_settings()['config']

    @decorators.idempotent_id('63183377-251f-4622-81f0-6b58a8a285c9')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain_config_default")
    def test_show_default_group_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_default_group_config('identity')['config']

    @decorators.idempotent_id('6440e9c1-e8da-474d-9118-89996fffe5f8')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_domain_config_default")
    def test_show_default_group_option(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.show_default_group_option('identity', 'driver')['config']

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_domain_config")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd116')
    def test_update_domain_config(self):
        updated_config = {'ldap': {'url': data_utils.rand_url()}}
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_domain_config(
            self.domain_id, **updated_config)['config']

    @decorators.idempotent_id('6e32bf96-dbe9-4ac8-b814-0e79fa948285')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_domain_config")
    def test_update_domain_group_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_domain_group_config(
            self.domain_id, 'identity', identity=self.identity)['config']

    @decorators.idempotent_id('d2c510da-a077-4c67-9522-27745ef2812b')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_domain_config")
    def test_update_domain_group_option_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.update_domain_group_option_config(
            self.domain_id, 'identity', 'driver', driver='ldap')['config']

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_domain_config")
    @decorators.idempotent_id('6bdaecd4-0843-4ed6-ab64-3a57ab0cd117')
    def test_delete_domain_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_domain_config(self.domain_id)

    @decorators.idempotent_id('f479694b-df02-4d5a-88b6-c8b52f9341eb')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_domain_config")
    def test_delete_domain_group_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_domain_group_config(self.domain_id, 'identity')

    @decorators.idempotent_id('f594bde3-31c9-414f-922d-0ddafdc0ca40')
    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_domain_config")
    def test_delete_domain_group_option_config(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.client.delete_domain_group_option_config(
            self.domain_id, 'identity', 'driver')
