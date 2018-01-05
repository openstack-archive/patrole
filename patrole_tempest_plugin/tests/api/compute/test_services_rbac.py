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


class ServicesRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(ServicesRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-services', 'compute'):
            raise cls.skipException(
                '%s skipped as os-services not enabled' % cls.__name__)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-services")
    @decorators.idempotent_id('7472261b-9c6d-453a-bcb3-aecaa29ad281')
    def test_list_services(self):
        with self.rbac_utils.override_role(self):
            self.services_client.list_services()['services']
