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

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class ExtensionsRbacTest(rbac_base.BaseVolumeRbacTest):

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:list_extensions")
    @decorators.idempotent_id('7f2dcc41-e850-493f-a400-82db4e2b50c0')
    def test_list_extensions(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.volumes_extension_client.list_extensions()


class ExtensionsV3RbacTest(ExtensionsRbacTest):
    _api_version = 3
