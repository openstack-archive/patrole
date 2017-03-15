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
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeHostsAdminRbacTest(rbac_base.BaseVolumeAdminRbacTest):

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume_extension:hosts")
    @decorators.idempotent_id('64e837f5-5452-4e26-b934-c721ea7a8644')
    def test_list_hosts(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.volume_hosts_client.list_hosts()
