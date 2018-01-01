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


class MigrationsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(MigrationsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-migrations', 'compute'):
            msg = "%s skipped as os-migrations not enabled." % cls.__name__
            raise cls.skipException(msg)

    @decorators.idempotent_id('5795231c-3729-448c-a072-9a225db1a328')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-migrations:index")
    def test_list_services(self):
        with self.rbac_utils.override_role(self):
            self.migrations_client.list_migrations()
