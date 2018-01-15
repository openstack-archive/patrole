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
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class SecGroupRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(SecGroupRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('security-group', 'network'):
            msg = "security-group extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(SecGroupRbacTest, cls).resource_setup()
        secgroup_name = data_utils.rand_name(cls.__name__ + '-secgroup')
        cls.secgroup = cls.security_groups_client.create_security_group(
            name=secgroup_name)['security_group']
        cls.addClassResourceCleanup(
            cls.security_groups_client.delete_security_group,
            cls.secgroup['id'])

    def _create_security_group(self):
        # Create a security group
        name = data_utils.rand_name(self.__class__.__name__ + '-secgroup')
        security_group =\
            self.security_groups_client.create_security_group(
                name=name)['security_group']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.security_groups_client.delete_security_group,
            security_group['id'])
        return security_group

    def _create_security_group_rule(self):
        # Create a security group rule
        sec_group_rule = \
            self.security_group_rules_client.create_security_group_rule(
                security_group_id=self.secgroup['id'],
                direction='ingress',
                protocol='tcp',
                port_range_min=99,
                port_range_max=99)['security_group_rule']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.security_group_rules_client.delete_security_group_rule,
            sec_group_rule['id'])
        return sec_group_rule

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_security_group")
    @decorators.idempotent_id('db7003ce-5717-4e5b-afc7-befa35e8c67f')
    def test_create_security_group(self):

        with self.rbac_utils.override_role(self):
            self._create_security_group()

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_security_group",
                                 expected_error_code=404)
    @decorators.idempotent_id('56335e77-aef2-4b54-86c7-7f772034b585')
    def test_show_security_groups(self):

        with self.rbac_utils.override_role(self):
            self.security_groups_client.show_security_group(
                self.secgroup['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_security_group",
                                 expected_error_code=404)
    @decorators.idempotent_id('0b1330fd-dd28-40f3-ad73-966052e4b3de')
    def test_delete_security_group(self):

        # Create a security group
        secgroup_id = self._create_security_group()['id']

        with self.rbac_utils.override_role(self):
            self.security_groups_client.delete_security_group(secgroup_id)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_security_group",
                                 expected_error_code=404)
    @decorators.idempotent_id('56c5e4dc-f8aa-11e6-bc64-92361f002671')
    def test_update_security_group(self):

        # Create a security group
        secgroup_id = self._create_security_group()['id']

        with self.rbac_utils.override_role(self):
            self.security_groups_client.update_security_group(
                secgroup_id,
                description="test description")

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_security_groups")
    @decorators.idempotent_id('fbaf8d96-ed3e-49af-b24c-5fb44f05bbb7')
    def test_list_security_groups(self):

        with self.rbac_utils.override_role(self):
            self.security_groups_client.list_security_groups()

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_security_group_rule")
    @decorators.idempotent_id('953d78df-00cd-416f-9cbd-b7cb4ea65772')
    def test_create_security_group_rule(self):

        with self.rbac_utils.override_role(self):
            self._create_security_group_rule()

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_security_group_rule",
                                 expected_error_code=404)
    @decorators.idempotent_id('2262539e-b7d9-438c-acf9-a5ce0613be28')
    def test_delete_security_group_rule(self):

        sec_group_rule = self._create_security_group_rule()
        with self.rbac_utils.override_role(self):
            self.security_group_rules_client.delete_security_group_rule(
                sec_group_rule['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_security_group_rule",
                                 expected_error_code=404)
    @decorators.idempotent_id('84b4038c-261e-4a94-90d5-c885739ab0d5')
    def test_show_security_group_rule(self):

        sec_group_rule = self._create_security_group_rule()
        with self.rbac_utils.override_role(self):
            self.security_group_rules_client.show_security_group_rule(
                sec_group_rule['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_security_group_rules")
    @decorators.idempotent_id('05739ab6-fa35-11e6-bc64-92361f002671')
    def test_list_security_group_rules(self):

        with self.rbac_utils.override_role(self):
            self.security_group_rules_client.list_security_group_rules()
