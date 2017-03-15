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

from tempest.lib import decorators
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class ConfigDriveRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ConfigDriveRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def skip_checks(cls):
        super(ConfigDriveRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-config-drive', 'compute'):
            msg = "%s skipped as os-config-drive extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)

    @decorators.idempotent_id('55c62ef7-b72b-4970-acc6-05b0a4316e5d')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-config-drive")
    def test_create_test_server_with_config_drive(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # NOTE(felipemonteiro): This policy action is always enforced,
        # regardless whether the config_drive flag is set to true or false.
        # However, it has been explicitly set to true below, in case that this
        # behavior ever changes in the future.
        self.create_test_server(config_drive=True)
