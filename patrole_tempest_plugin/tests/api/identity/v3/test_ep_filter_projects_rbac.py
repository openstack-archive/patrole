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

from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


class EndpointFilterProjectsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def resource_setup(cls):
        super(EndpointFilterProjectsV3RbacTest, cls).resource_setup()
        cls.project = cls.setup_test_project()
        cls.endpoint = cls.setup_test_endpoint()

    def _add_endpoint_to_project(self, ignore_not_found=False):
        self.endpoint_filter_client.add_endpoint_to_project(
            self.project['id'], self.endpoint['id'])

        if ignore_not_found:
            self.addCleanup(
                test_utils.call_and_ignore_notfound_exc,
                self.endpoint_filter_client.delete_endpoint_from_project,
                self.project['id'], self.endpoint['id'])
        else:
            self.addCleanup(
                self.endpoint_filter_client.delete_endpoint_from_project,
                self.project['id'], self.endpoint['id'])

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:add_endpoint_to_project"])
    @decorators.idempotent_id('9199ec13-816d-4efe-b8b1-e1cd026b9747')
    def test_add_endpoint_to_project(self):
        # Adding endpoints to projects
        with self.override_role():
            self._add_endpoint_to_project(ignore_not_found=True)

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:list_projects_for_endpoint"])
    @decorators.idempotent_id('f53dca42-ec8a-48e9-924b-0bbe6c99727f')
    def test_list_projects_for_endpoint(self):
        with self.override_role():
            self.endpoint_filter_client.list_projects_for_endpoint(
                self.endpoint['id'])

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:check_endpoint_in_project"])
    @decorators.idempotent_id('0c1425eb-833c-4aa1-a21d-52ffa41fdc6a')
    def test_check_endpoint_in_project(self):
        self._add_endpoint_to_project()
        with self.override_role():
            self.endpoint_filter_client.check_endpoint_in_project(
                self.project['id'], self.endpoint['id'])

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:list_endpoints_for_project"])
    @decorators.idempotent_id('5d86c659-c6ad-41e0-854e-3823e95c7cc2')
    def test_list_endpoints_in_project(self):
        with self.override_role():
            self.endpoint_filter_client.list_endpoints_in_project(
                self.project['id'])

    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:remove_endpoint_from_project"])
    @decorators.idempotent_id('b4e21c10-4f47-427b-9b8a-f5b5601adfda')
    def test_remove_endpoint_from_project(self):
        self._add_endpoint_to_project(ignore_not_found=True)
        with self.override_role():
            self.endpoint_filter_client.delete_endpoint_from_project(
                self.project['id'], self.endpoint['id'])
