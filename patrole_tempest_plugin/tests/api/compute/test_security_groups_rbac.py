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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class SecurtiyGroupsRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """Tests non-deprecated security group policies. Requires network service.

    This class tests non-deprecated policies for adding and removing a security
    group to and from a server.
    """

    @classmethod
    def skip_checks(cls):
        super(SecurtiyGroupsRbacTest, cls).skip_checks()
        # All the tests below require the network service.
        # NOTE(gmann) Currently 'network' service is always True in
        # utils.get_service_list() So below check is not much of use.
        # Commenting the below check as Tempest is moving the get_service_list
        # from test.py to utils.
        # If we want to check 'network' service availability, then
        # get_service_list can be used from new location.
        # if not utils.get_service_list()['network']:
        #    raise cls.skipException(
        #        'Skipped because the network service is not available')

    @classmethod
    def setup_credentials(cls):
        # A network and a subnet will be created for these tests.
        cls.set_network_resources(network=True, subnet=True)
        super(SecurtiyGroupsRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(SecurtiyGroupsRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('3db159c6-a467-469f-9a25-574197885520')
    def test_list_security_groups_by_server(self):
        with self.rbac_utils.override_role(self):
            self.servers_client.list_security_groups_by_server(
                self.server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('ea1ca73f-2d1d-43cb-9a46-900d7927b357')
    def test_create_security_group_for_server(self):
        sg_name = self.create_security_group()['name']

        with self.rbac_utils.override_role(self):
            self.servers_client.add_security_group(self.server['id'],
                                                   name=sg_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.servers_client.remove_security_group,
                        self.server['id'], name=sg_name)

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('0ad2e856-e2d3-4ac5-a620-f93d0d3d2626')
    def test_remove_security_group_from_server(self):
        sg_name = self.create_security_group()['name']

        self.servers_client.add_security_group(self.server['id'], name=sg_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.servers_client.remove_security_group,
                        self.server['id'], name=sg_name)

        with self.rbac_utils.override_role(self):
            self.servers_client.remove_security_group(
                self.server['id'], name=sg_name)


class SecurityGroupsRbacMaxV235Test(rbac_base.BaseV2ComputeRbacTest):

    # Tests in this class will fail with a 404 from microversion 2.36,
    # according to:
    # https://developer.openstack.org/api-ref/compute/#security-groups-os-security-groups-deprecated
    max_microversion = '2.35'

    @classmethod
    def skip_checks(cls):
        super(SecurityGroupsRbacMaxV235Test, cls).skip_checks()
        # All the tests below require the network service.
        # NOTE(gmann) Currently 'network' service is always True in
        # utils.get_service_list() So below check is not much of use.
        # Commenting the below check as Tempest is moving the get_service_list
        # from test.py to utils.
        # If we want to check 'network' service availability, then
        # get_service_list can be used from new location.
        # if not utils.get_service_list()['network']:
        #    raise cls.skipException(
        #        'Skipped because the network service is not available')

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('4ac58e49-48c1-4fca-a6c3-3f95fb99eb77')
    def test_list_security_groups(self):
        with self.rbac_utils.override_role(self):
            self.security_groups_client.list_security_groups()

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('e8fe7f5a-69ee-412d-81d3-a8c7a488b54d')
    def test_create_security_groups(self):
        with self.rbac_utils.override_role(self):
            self.create_security_group()['id']

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('59127e8e-302d-11e7-93ae-92361f002671')
    def test_delete_security_groups(self):
        sec_group_id = self.create_security_group()['id']
        with self.rbac_utils.override_role(self):
            self.security_groups_client.delete_security_group(sec_group_id)

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('3de5c6bc-b822-469e-a627-82427d38b067')
    def test_update_security_groups(self):
        sec_group_id = self.create_security_group()['id']
        new_name = data_utils.rand_name()
        new_desc = data_utils.rand_name()

        with self.rbac_utils.override_role(self):
            self.security_groups_client.update_security_group(
                sec_group_id, name=new_name, description=new_desc)

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-security-groups"])
    @decorators.idempotent_id('6edc0320-302d-11e7-93ae-92361f002671')
    def test_show_security_groups(self):
        sec_group_id = self.create_security_group()['id']
        with self.rbac_utils.override_role(self):
            self.security_groups_client.show_security_group(sec_group_id)
