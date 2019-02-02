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


class IdentityRoleAssignmentsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @decorators.idempotent_id('afe57adb-1b9c-43d9-84a9-f0cf4c94e416')
    @rbac_rule_validation.action(service="keystone",
                                 rules=["identity:list_role_assignments"])
    def test_list_role_assignments(self):
        with self.override_role():
            self.role_assignments_client.list_role_assignments()

    @decorators.idempotent_id('36c7a990-857e-415c-8717-38d7200a9894')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:list_role_assignments_for_tree"])
    def test_list_role_assignments_for_tree(self):
        project = self.setup_test_project()

        with self.override_role():
            self.role_assignments_client.list_role_assignments(
                include_subtree=True,
                **{'scope.project.id': project['id']})
