# Copyright 2017 AT&T Corporation
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
from patrole_tempest_plugin.tests.api.orchestration import rbac_base


class ResourceTypesRbacTest(rbac_base.BaseOrchestrationRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ResourceTypesRbacTest, cls).setup_clients()
        cls.client = cls.orchestration_client

    @classmethod
    def resource_setup(cls):
        super(ResourceTypesRbacTest, cls).resource_setup()

        cls.resource_types = cls.client.list_resource_types()['resource_types']

        # There should always be several resource types on a system. But just
        # in case there are none, skip these tests, as that implies the system
        # is misconfigured.
        if cls.resource_types:
            cls.resource_type_name = cls.resource_types[0]
        else:
            raise cls.skipException('No resource types found.')

    @decorators.idempotent_id('56c06e92-df96-47b5-bcf2-0104e74e2511')
    @rbac_rule_validation.action(service="heat",
                                 rule="stacks:list_resource_types")
    def test_list_resource_types(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_resource_types()['resource_types']

    @decorators.idempotent_id('8b0290f9-0d53-479e-8e4d-3d865b0107a4')
    @rbac_rule_validation.action(service="heat",
                                 rule="stacks:generate_template")
    def test_show_resource_type_template(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_resource_type_template(self.resource_type_name)

    @decorators.idempotent_id('2cdcd47f-6abe-43af-b736-c188df27dd38')
    @rbac_rule_validation.action(service="heat",
                                 rule="stacks:resource_schema")
    def test_show_resource_type_schema(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_resource_type(self.resource_type_name)[
            'resource_type']
