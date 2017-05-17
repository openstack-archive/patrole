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
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeServicesRbacTest(rbac_base.BaseVolumeRbacTest):

    # TODO(felipemonteiro): Implement a test to cover the policy action,
    # "volume_extension:services:update", once the Tempest client endpoint
    # is implemented.

    @classmethod
    def skip_checks(cls):
        super(VolumeServicesRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('os-services', 'volume'):
            msg = "%s skipped as os-services not enabled." % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(VolumeServicesRbacTest, cls).setup_clients()
        cls.services_client = cls.os_primary.volume_services_v2_client

    @decorators.idempotent_id('b9134f01-97c0-4abd-9455-fe2f03e3f966')
    @rbac_rule_validation.action(
        service="cinder",
        rule="volume_extension:services:index")
    def test_list_services(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.services_client.list_services()['services']


class VolumeServicesV3RbacTest(VolumeServicesRbacTest):
    _api_version = 3
