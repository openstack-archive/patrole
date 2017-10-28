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

import testtools

from tempest.common import utils
from tempest.common import waiters
from tempest import config
from tempest.lib.common import api_version_utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class ServerActionsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    credentials = ['primary', 'admin']

    @classmethod
    def resource_setup(cls):
        super(ServerActionsRbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']
        cls.flavor_ref = CONF.compute.flavor_ref
        cls.flavor_ref_alt = CONF.compute.flavor_ref_alt
        cls.image_ref = CONF.compute.image_ref

    def setUp(self):
        super(ServerActionsRbacTest, self).setUp()
        try:
            waiters.wait_for_server_status(self.servers_client,
                                           self.server_id, 'ACTIVE')
        except lib_exc.NotFound:
            # If the server was found to be deleted by a previous test,
            # a new one is built
            server = self.create_test_server(wait_until='ACTIVE')
            self.__class__.server_id = server['id']
        except Exception:
            # Recreating the server in case something happened during a test
            self.__class__.server_id = self.recreate_server(self.server_id)

    def _stop_server(self):
        self.servers_client.stop_server(self.server_id)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'SHUTOFF')

    def _resize_server(self, flavor):
        self.servers_client.resize_server(self.server_id, flavor)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'VERIFY_RESIZE')

    def _confirm_resize_server(self):
        self.servers_client.confirm_resize_server(self.server_id)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:stop")
    @decorators.idempotent_id('ab4a17d2-166f-4a6d-9944-f17baa576cf2')
    def test_stop_server(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._stop_server()

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:start")
    @decorators.idempotent_id('8876bfa9-4d10-406e-a335-a57e451abb12')
    def test_start_server(self):
        self._stop_server()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.start_server(self.server_id)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:resize")
    @decorators.idempotent_id('0546fbdd-2d8f-4ce8-ac00-f1e2129d0765')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_resize_server(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._resize_server(self.flavor_ref_alt)

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:revert_resize")
    @decorators.idempotent_id('d41b64b8-a72d-414a-a4c5-94e1eb5e5a96')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_revert_resize_server(self):
        self._resize_server(self.flavor_ref_alt)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.revert_resize_server(self.server_id)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')

    @decorators.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:confirm_resize")
    @decorators.idempotent_id('f51620cb-dfcb-4e5d-b421-2e0edaa1316e')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_confirm_resize_server(self):
        self._resize_server(self.flavor_ref_alt)
        self.addCleanup(self._confirm_resize_server)
        self.addCleanup(self._resize_server, self.flavor_ref)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._confirm_resize_server()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:rebuild")
    @decorators.idempotent_id('54b1a30b-c96c-472c-9c83-ccaf6ec7e20b')
    def test_rebuild_server(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.rebuild_server(self.server_id, self.image_ref)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:reboot")
    @decorators.idempotent_id('19f27856-56e1-44f8-8615-7257f6b85cbb')
    def test_reboot_server(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.reboot_server(self.server_id, type='HARD')
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:index")
    @decorators.idempotent_id('631f0d86-7607-4198-8312-9da2f05464a4')
    def test_server_index(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_servers(minimal=True)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:detail")
    @decorators.idempotent_id('96093480-3ce5-4a8b-b569-aed870379c24')
    def test_server_detail(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_servers(detail=True)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:detail:get_all_tenants")
    @decorators.idempotent_id('a9e5a1c0-acfe-49a2-b2b1-fd8b19d61f71')
    def test_server_detail_all_tenants(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_servers(detail=True, all_tenants=1)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:index:get_all_tenants")
    @decorators.idempotent_id('4b93ba56-69e6-41f5-82c4-84a5c4c42091')
    def test_server_index_all_tenants(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_servers(minimal=True, all_tenants=1)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:show")
    @decorators.idempotent_id('eaaf4f51-31b5-497f-8f0f-f527e5f70b83')
    def test_show_server(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_server(self.server_id)

    @utils.services('image')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:create_image")
    @decorators.idempotent_id('ba0ac859-99f4-4055-b5e0-e0905a44d331')
    def test_create_image(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        # This function will also call show image
        self.create_image_from_server(self.server_id, wait_until='ACTIVE')

    @utils.services('image', 'volume')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:create_image:allow_volume_backed")
    @decorators.idempotent_id('8b869f73-49b3-4cc4-a0ce-ef64f8e1d6f9')
    def test_create_image_from_volume_backed_server(self):
        # volume_backed=True creates a volume and create server will be
        # requested with 'block_device_mapping_v2' with necessary values for
        # this test.
        server = self.create_test_server(volume_backed=True,
                                         wait_until='ACTIVE')
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        # This function will also call show image.
        image = self.create_image_from_server(server['id'],
                                              wait_until='ACTIVE',
                                              wait_for_server=False)
        self.addCleanup(self.compute_images_client.wait_for_resource_deletion,
                        image['id'])
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.compute_images_client.delete_image, image['id'])

    @decorators.idempotent_id('9fdd4630-731c-4f7c-bce5-69fa3792c52a')
    @testtools.skipUnless(CONF.compute_feature_enabled.snapshot,
                          'Snapshotting not available, backup not possible.')
    @utils.services('image')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-create-backup")
    def test_create_backup(self):
        # Prioritize glance v2 over v1 for deleting/waiting for image status.
        if CONF.image_feature_enabled.api_v2:
            glance_admin_client = self.os_admin.image_client_v2
        elif CONF.image_feature_enabled.api_v1:
            glance_admin_client = self.os_admin.image_client
        else:
            raise lib_exc.InvalidConfiguration(
                'Either api_v1 or api_v2 must be True in '
                '[image-feature-enabled].')

        backup_name = data_utils.rand_name(self.__class__.__name__ + '-Backup')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        resp = self.servers_client.create_backup(
            self.server_id, backup_type='daily', rotation=1,
            name=backup_name).response

        # Prior to microversion 2.45, image ID must be parsed from location
        # header. With microversion 2.45+, image_id is returned.
        if api_version_utils.compare_version_header_to_response(
                "OpenStack-API-Version", "2.45", resp, "lt"):
            image_id = resp['image_id']
        else:
            image_id = data_utils.parse_image_id(resp['location'])

        # Use admin credentials to wait since waiting involves show, which is
        # a different policy.
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        glance_admin_client.delete_image, image_id)
        waiters.wait_for_image_status(glance_admin_client, image_id, 'active')


class ServerActionsV214RbacTest(rbac_base.BaseV2ComputeRbacTest):

    min_microversion = '2.14'
    max_microversion = 'latest'

    @classmethod
    def resource_setup(cls):
        super(ServerActionsV214RbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-evacuate")
    @decorators.idempotent_id('78ecef3c-faff-412a-83be-47651963eb21')
    def test_evacuate_server(self):
        fake_host_name = data_utils.rand_name(
            self.__class__.__name__ + '-fake-host')

        # NOTE(felipemonteiro): Because evacuating a server is a risky action
        # to test in the gates, a 404 is coerced using a fake host. However,
        # the policy check is done before the 404 is thrown.
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.assertRaisesRegex(lib_exc.NotFound,
                               "Compute host %s not found." % fake_host_name,
                               self.servers_client.evacuate_server,
                               self.server_id,
                               host=fake_host_name)


class ServerActionsV216RbacTest(rbac_base.BaseV2ComputeRbacTest):

    # This class has test case(s) that requires at least microversion 2.16.
    # See the following link for details:
    # https://developer.openstack.org/api-ref/compute/#show-server-details
    min_microversion = '2.16'
    max_microversion = 'latest'

    @classmethod
    def resource_setup(cls):
        super(ServerActionsV216RbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:show:host_status")
    @decorators.idempotent_id('736da575-86f8-4b2a-9902-dd37dc9a409b')
    def test_show_server_host_status(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        server = self.servers_client.show_server(self.server_id)['server']

        if 'host_status' not in server:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute='host_status')
