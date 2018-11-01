# Copyright 2018 AT&T Corporation.
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


class AddressScopeExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AddressScopeExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('address-scope', 'network'):
            msg = "address-scope extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(AddressScopeExtRbacTest, cls).resource_setup()
        cls.network = cls.create_network()

    def _create_address_scope(self, name=None, **kwargs):
        name = name or data_utils.rand_name(self.__class__.__name__)
        address_scope = self.ntp_client.create_address_scope(name=name,
                                                             ip_version=6,
                                                             **kwargs)
        address_scope = address_scope['address_scope']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.ntp_client.delete_address_scope,
                        address_scope['id'])
        return address_scope

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_address_scope"],
                                 expected_error_codes=[403])
    @decorators.idempotent_id('8cb2d6b5-23c2-4648-997b-7a6ae55be3ad')
    def test_create_address_scope(self):

        """Create Address Scope

        RBAC test for the neutron create_address_scope policy
        """
        with self.rbac_utils.override_role(self):
            self._create_address_scope()

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_address_scope",
                                        "create_address_scope:shared"],
                                 expected_error_codes=[403, 403])
    @decorators.idempotent_id('0c3f55c0-6ebe-4251-afca-62c5cb4632ca')
    def test_create_address_scope_shared(self):

        """Create Shared Address Scope

        RBAC test for the neutron create_address_scope:shared policy
        """
        with self.rbac_utils.override_role(self):
            self._create_address_scope(shared=True)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_address_scope"],
                                 expected_error_codes=[404])
    @decorators.idempotent_id('a53f741b-46f6-412f-936f-ac920d449da8')
    def test_get_address_scope(self):

        """Get Address Scope

        RBAC test for the neutron get_address_scope policy
        """
        address_scope = self._create_address_scope()
        with self.rbac_utils.override_role(self):
            self.ntp_client.show_address_scope(address_scope['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_address_scope",
                                        "update_address_scope"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('3ce4d606-e067-4ef5-840f-96c680226e73')
    def test_update_address_scope(self):

        """Update Address Scope

        RBAC test for neutron update_address_scope policy
        """
        address_scope = self._create_address_scope()
        name = data_utils.rand_name(self.__class__.__name__)
        with self.rbac_utils.override_role(self):
            self.ntp_client.update_address_scope(address_scope['id'],
                                                 name=name)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_address_scope",
                                        "update_address_scope",
                                        "update_address_scope:shared"],
                                 expected_error_codes=[404, 403, 403])
    @decorators.idempotent_id('77d3a9d2-721a-4d9f-9654-6b52f113df85')
    def test_update_address_scope_shared(self):

        """Update Shared Address Scope

        RBAC test for neutron update_address_scope:shared policy
        """
        address_scope = self._create_address_scope(shared=True)
        with self.rbac_utils.override_role(self):
            self.ntp_client.update_address_scope(address_scope['id'],
                                                 shared=True)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_address_scope",
                                        "delete_address_scope"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('277d8e47-e498-4452-b969-a91f747296ba')
    def test_delete_address_scope(self):

        """Delete Address Scope

        RBAC test for neutron delete_address_scope policy
        """
        address_scope = self._create_address_scope()
        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_address_scope(address_scope['id'])
