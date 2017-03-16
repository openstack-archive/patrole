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

from oslo_log import log
import testtools

from tempest.common import waiters
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class ServerActionsRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(ServerActionsRbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def resource_setup(cls):
        cls.set_validation_resources()
        super(ServerActionsRbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE',
                                               validatable=True)['id']
        cls.flavor_ref = CONF.compute.flavor_ref
        cls.flavor_ref_alt = CONF.compute.flavor_ref_alt
        cls.image_ref = CONF.compute.image_ref

    def setUp(self):
        super(ServerActionsRbacTest, self).setUp()
        try:
            waiters.wait_for_server_status(self.client,
                                           self.server_id, 'ACTIVE')
        except lib_exc.NotFound:
            # if the server was found to be deleted by a previous test,
            # a new one is built
            server = self.create_test_server(
                validatable=True,
                wait_until='ACTIVE')
            self.__class__.server_id = server['id']
        except Exception:
            # Rebuilding the server in case something happened during a test
            self.__class__.server_id = self.rebuild_server(
                self.server_id, validatable=True)

    def _test_start_server(self):
        self.client.start_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'ACTIVE')

    def _test_stop_server(self):
        self.client.stop_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'SHUTOFF')

    def _test_resize_server(self, flavor):
        self.client.resize_server(self.server_id, flavor)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'VERIFY_RESIZE')

    def _test_revert_resize_server(self):
        self.client.revert_resize_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'ACTIVE')

    def _test_confirm_resize_server(self):
        self.client.confirm_resize_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:stop")
    @decorators.idempotent_id('ab4a17d2-166f-4a6d-9944-f17baa576cf2')
    def test_stop_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._test_stop_server()

    @test.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:start")
    @decorators.idempotent_id('8876bfa9-4d10-406e-a335-a57e451abb12')
    def test_start_server(self):
        self._test_stop_server()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._test_start_server()

    @test.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:resize")
    @decorators.idempotent_id('0546fbdd-2d8f-4ce8-ac00-f1e2129d0765')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_resize_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._test_resize_server(self.flavor_ref_alt)

    @test.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:revert_resize")
    @decorators.idempotent_id('d41b64b8-a72d-414a-a4c5-94e1eb5e5a96')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_revert_resize_server(self):
        self._test_resize_server(self.flavor_ref_alt)
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._test_revert_resize_server()

    @test.attr(type='slow')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:confirm_resize")
    @decorators.idempotent_id('f51620cb-dfcb-4e5d-b421-2e0edaa1316e')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_confirm_resize_server(self):
        self._test_resize_server(self.flavor_ref_alt)
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.addCleanup(
            lambda: (self._test_resize_server(self.flavor_ref),
                     self._test_confirm_resize_server())
        )
        self._test_confirm_resize_server()

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:rebuild")
    @decorators.idempotent_id('54b1a30b-c96c-472c-9c83-ccaf6ec7e20b')
    def test_rebuild_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.rebuild_server(self.server_id, self.image_ref)
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:reboot")
    @decorators.idempotent_id('19f27856-56e1-44f8-8615-7257f6b85cbb')
    def test_reboot_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.reboot_server(self.server_id, type='HARD')
        waiters.wait_for_server_status(self.client, self.server_id,
                                       'ACTIVE')

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:index")
    @decorators.idempotent_id('631f0d86-7607-4198-8312-9da2f05464a4')
    def test_server_index(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_servers(minimal=True)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:detail")
    @decorators.idempotent_id('96093480-3ce5-4a8b-b569-aed870379c24')
    def test_server_detail(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_servers(detail=True)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:detail:get_all_tenants")
    @decorators.idempotent_id('a9e5a1c0-acfe-49a2-b2b1-fd8b19d61f71')
    def test_server_detail_all_tenants(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_servers(detail=True, all_tenants=1)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:index:get_all_tenants")
    @decorators.idempotent_id('4b93ba56-69e6-41f5-82c4-84a5c4c42091')
    def test_server_index_all_tenants(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_servers(minimal=True, all_tenants=1)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:show")
    @decorators.idempotent_id('eaaf4f51-31b5-497f-8f0f-f527e5f70b83')
    def test_show_server(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.show_server(self.server_id)


class ServerActionsV216RbacTest(rbac_base.BaseV2ComputeRbacTest):

    # This class has test case(s) that requires at least version 2.16.
    #
    # See the following link for details:
    # http://developer.openstack.org/
    # api-ref-compute-v2.1.html#show-server-details

    min_microversion = '2.16'
    max_microversion = 'latest'

    @classmethod
    def setup_clients(cls):
        super(ServerActionsV216RbacTest, cls).setup_clients()
        cls.client = cls.servers_client

    @classmethod
    def resource_setup(cls):
        cls.set_validation_resources()
        super(ServerActionsV216RbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE',
                                               validatable=True)['id']

    def setUp(self):
        super(ServerActionsV216RbacTest, self).setUp()
        try:
            waiters.wait_for_server_status(self.client,
                                           self.server_id, 'ACTIVE')
        except lib_exc.NotFound:
            # if the server was found to be deleted by a previous test,
            # a new one is built
            server = self.create_test_server(
                validatable=True,
                wait_until='ACTIVE')
            self.__class__.server_id = server['id']
        except Exception:
            # Rebuilding the server in case something happened during a test
            self.__class__.server_id = self.rebuild_server(
                self.server_id, validatable=True)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:show:host_status")
    @decorators.idempotent_id('736da575-86f8-4b2a-9902-dd37dc9a409b')
    def test_show_server_host_status(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        server = self.client.show_server(self.server_id)['server']

        if 'host_status' not in server:
            LOG.info("host_status attribute not returned when role doesn't "
                     "have permission to access it.")
            raise rbac_exceptions.RbacActionFailed
