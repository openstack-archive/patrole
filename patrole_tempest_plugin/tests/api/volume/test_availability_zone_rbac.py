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
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class AvailabilityZoneRbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(AvailabilityZoneRbacTest, cls).setup_clients()
        cls.client = cls.availability_zone_client

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(AvailabilityZoneRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="cinder",
                                 rule="volume:availability_zone_list")
    @decorators.idempotent_id('8cfd920c-4b6c-402d-b6e2-ede86bedc702')
    def test_get_availability_zone_list(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_availability_zones()
