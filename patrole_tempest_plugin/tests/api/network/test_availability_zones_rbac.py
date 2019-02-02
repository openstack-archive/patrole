# Copyright 2018 AT&T Corporation.
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

from tempest.common import utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class AvailabilityZoneExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(AvailabilityZoneExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('availability_zone',
                                          'network'):
            msg = "network_availability_zone extension not enabled."
            raise cls.skipException(msg)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_availability_zone"])
    @decorators.idempotent_id('3c521be8-c32e-11e8-a611-080027758b73')
    def test_list_availability_zone_rbac(self):

        """List all available zones.

        RBAC test for the neutron ``list_availability_zones``
        function and the ``get_availability_zone`` policy
        """
        admin_resources = (self.ntp_client.list_availability_zones()
                           ["availability_zones"])
        with self.override_role_and_validate_list(
                admin_resources=admin_resources) as ctx:
            ctx.resources = (self.ntp_client.list_availability_zones()
                             ['availability_zones'])
