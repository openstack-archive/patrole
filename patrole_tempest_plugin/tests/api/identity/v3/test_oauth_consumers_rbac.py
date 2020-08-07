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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class IdentityConsumersV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    def _create_consumer(self):
        description = data_utils.rand_name(
            self.__class__.__name__)
        consumer = self.consumers_client.create_consumer(
            description)['consumer']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.consumers_client.delete_consumer,
                        consumer['id'])
        return consumer

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:create_consumer"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d970')
    def test_create_consumer(self):
        with self.override_role():
            self._create_consumer()

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:delete_consumer"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d971')
    def test_delete_consumer(self):
        consumer = self._create_consumer()

        with self.override_role():
            self.consumers_client.delete_consumer(consumer['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:update_consumer"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d972')
    def test_update_consumer(self):
        consumer = self._create_consumer()
        updated_description = data_utils.rand_name(
            self.__class__.__name__)

        with self.override_role():
            self.consumers_client.update_consumer(consumer['id'],
                                                  updated_description)

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:get_consumer"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d973')
    def test_show_consumer(self):
        consumer = self._create_consumer()

        with self.override_role():
            self.consumers_client.show_consumer(consumer['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_consumers"])
    @decorators.idempotent_id('0f148510-63bf-11e6-4522-080044d0d975')
    def test_list_consumers(self):
        with self.override_role():
            self.consumers_client.list_consumers()
