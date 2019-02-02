#    Copyright 2017 AT&T Corporation.
#    All Rights Reserved.
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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class ServerGroupsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(ServerGroupsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-server-groups', 'compute'):
            msg = "%s skipped as os-server-groups not enabled." % cls.__name__
            raise cls.skipException(msg)

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-groups:create"])
    @decorators.idempotent_id('7f3eae94-6130-47e9-81ac-34009f55be2f')
    def test_create_server_group(self):
        with self.override_role():
            self.create_test_server_group()

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-groups:delete"])
    @decorators.idempotent_id('832d9be3-632e-47b2-93d2-5897db43e3e2')
    def test_delete_server_group(self):
        server_group = self.create_test_server_group()
        with self.override_role():
            self.server_groups_client.delete_server_group(server_group['id'])

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-groups:index"])
    @decorators.idempotent_id('5eccd67f-5945-483b-b1c8-de851ebfc1c1')
    def test_list_server_groups(self):
        with self.override_role():
            self.server_groups_client.list_server_groups()

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-groups:show"])
    @decorators.idempotent_id('62534e3f-7e99-4a3d-a08e-33e056460cf2')
    def test_show_server_group(self):
        server_group = self.create_test_server_group()
        with self.override_role():
            self.server_groups_client.show_server_group(server_group['id'])
