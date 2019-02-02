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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class FlavorsExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def resource_setup(cls):
        super(FlavorsExtRbacTest, cls).resource_setup()
        providers = cls.ntp_client.list_service_providers()
        if not providers["service_providers"]:
            raise cls.skipException("No service_providers available.")
        cls.service_type = providers["service_providers"][0]["service_type"]

    @decorators.idempotent_id('2632a61b-831e-4da5-82c8-a5f7d448589b')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_flavor"])
    def test_create_flavor(self):
        """Create flavor.

        RBAC test for the neutron "create_flavor" policy
        """
        with self.override_role():
            flavor = self.ntp_client.create_flavor(
                service_type=self.service_type)

        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor, flavor["flavor"]["id"])

    @decorators.idempotent_id('9c53164c-117d-4b44-a5cb-96f08386513f')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_flavor",
                                        "update_flavor"],
                                 expected_error_codes=[404, 403])
    def test_update_flavor(self):
        """Update flavor.

        RBAC test for the neutron "update_flavor" policy
        """
        flavor = self.ntp_client.create_flavor(service_type=self.service_type)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor, flavor["flavor"]["id"])

        name = data_utils.rand_name(self.__class__.__name__ + '-Flavor')
        with self.override_role():
            self.ntp_client.update_flavor(flavor["flavor"]["id"], name=name)

    @decorators.idempotent_id('1de15f9e-5080-4259-ab41-e230bb312de8')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_flavor",
                                        "delete_flavor"],
                                 expected_error_codes=[404, 403])
    def test_delete_flavor(self):
        """Delete flavor.

        RBAC test for the neutron "delete_flavor" policy
        """
        flavor = self.ntp_client.create_flavor(service_type=self.service_type)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor, flavor["flavor"]["id"])

        with self.override_role():
            self.ntp_client.delete_flavor(flavor["flavor"]["id"])

    @decorators.idempotent_id('c2baf35f-e6c1-4833-9114-aadd9b1f6aaa')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_flavor"],
                                 expected_error_codes=[404])
    def test_show_flavor(self):
        """Show flavor.

        RBAC test for the neutron "get_flavor" policy
        """
        flavor = self.ntp_client.create_flavor(service_type=self.service_type)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor, flavor["flavor"]["id"])

        with self.override_role():
            self.ntp_client.show_flavor(flavor["flavor"]["id"])

    @decorators.idempotent_id('ab10bd5d-987e-4255-966f-947670ffd0fa')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_flavor"])
    def test_list_flavors(self):
        """List flavors.

        RBAC test for the neutron "get_flavor" policy for "list_flavors" action
        """
        flavor = self.ntp_client.create_flavor(service_type=self.service_type)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor, flavor["flavor"]["id"])

        with self.override_role_and_validate_list(
            admin_resource_id=flavor["flavor"]["id"]
        ) as ctx:
            ctx.resources = self.ntp_client.list_flavors()['flavors']
