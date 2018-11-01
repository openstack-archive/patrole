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

from oslo_serialization import jsonutils as json

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
        with self.rbac_utils.override_role(self):
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
        with self.rbac_utils.override_role(self):
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

        with self.rbac_utils.override_role(self):
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

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_flavor(flavor["flavor"]["id"])

    @decorators.idempotent_id('ab10bd5d-987e-4255-966f-947670ffd0fa')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_flavors"])
    def test_list_flavors(self):
        """List flavors.

        RBAC test for the neutron "get_flavors" policy
        """
        flavor = self.ntp_client.create_flavor(service_type=self.service_type)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor, flavor["flavor"]["id"])

        with self.rbac_utils.override_role(self):
            self.ntp_client.list_flavors()


class FlavorsServiceProfileExtRbacTest(base.BaseNetworkExtRbacTest):
    @classmethod
    def resource_setup(cls):
        super(FlavorsServiceProfileExtRbacTest, cls).resource_setup()
        providers = cls.ntp_client.list_service_providers()
        if not providers["service_providers"]:
            raise cls.skipException("No service_providers available.")
        cls.service_type = providers["service_providers"][0]["service_type"]

        cls.flavor_id = cls.create_flavor()
        cls.service_profile_id = cls.create_service_profile()

    @classmethod
    def create_flavor(cls):
        flavor = cls.ntp_client.create_flavor(service_type=cls.service_type)
        flavor_id = flavor["flavor"]["id"]
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.ntp_client.delete_flavor, flavor_id)
        return flavor_id

    @classmethod
    def create_service_profile(cls):
        service_profile = cls.ntp_client.create_service_profile(
            metainfo=json.dumps({'foo': 'bar'}))
        service_profile_id = service_profile["service_profile"]["id"]
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.ntp_client.delete_service_profile, service_profile_id)
        return service_profile_id

    def create_flavor_service_profile(self, flavor_id, service_profile_id):
        self.ntp_client.create_flavor_service_profile(
            flavor_id, service_profile_id)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.ntp_client.delete_flavor_service_profile,
            flavor_id, service_profile_id)

    @decorators.idempotent_id('aa84b4c5-0dd6-4c34-aa81-3a76507f9b81')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_flavor_service_profile"])
    def test_create_flavor_service_profile(self):
        """Create flavor_service_profile.

        RBAC test for the neutron "create_flavor_service_profile" policy
        """
        with self.rbac_utils.override_role(self):
            self.create_flavor_service_profile(self.flavor_id,
                                               self.service_profile_id)

    @decorators.idempotent_id('3b680d9e-946a-4670-ab7f-0e4576675833')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["delete_flavor_service_profile"])
    def test_delete_flavor_service_profile(self):
        """Delete flavor_service_profile.

        RBAC test for the neutron "delete_flavor_service_profile" policy
        """
        self.create_flavor_service_profile(self.flavor_id,
                                           self.service_profile_id)

        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_flavor_service_profile(
                self.flavor_id, self.service_profile_id)
