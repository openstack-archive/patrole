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

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class MiscPolicyActionsRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """Test multiple policy actions that require a server to be created.

    Minimize the number of servers that need to be created across classes
    by consolidating test cases related to different policy "families" into
    one class. This reduces the risk of running into `BuildErrorException`
    errors being raised due to too many servers being created simultaneously
    especially when higher concurrency is used.

    Only applies to:
      * policy "families" that require server creation
      * small policy "families" -- i.e. containing one to three policies
    """

    @classmethod
    def resource_setup(cls):
        super(MiscPolicyActionsRbacTest, cls).resource_setup()
        cls.server_id = cls.create_test_server(wait_until='ACTIVE')['id']

    def setUp(self):
        super(MiscPolicyActionsRbacTest, self).setUp()
        try:
            waiters.wait_for_server_status(self.servers_client,
                                           self.server_id, 'ACTIVE')
        except lib_exc.NotFound:
            # If the server was found to be deleted by a previous test,
            # a new one is built
            server = self.create_test_server(wait_until='ACTIVE')
            self.__class__.server_id = server['id']
        except Exception:
            # Rebuilding the server in case something happened during a test
            self.__class__.server_id = self.rebuild_server(self.server_id)

    @test.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-actions:reset_state")
    @decorators.idempotent_id('ae84dd0b-f364-462e-b565-3457f9c019ef')
    def test_reset_server_state(self):
        """Test reset server state, part of os-admin-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.reset_state(self.server_id, state='error')
        self.addCleanup(self.servers_client.reset_state, self.server_id,
                        state='active')

    @test.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-actions:inject_network_info")
    @decorators.idempotent_id('ce48c340-51c1-4cff-9b6e-0cc5ef008630')
    def test_inject_network_info(self):
        """Test inject network info, part of os-admin-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.inject_network_info(self.server_id)

    @test.attr(type=['slow'])
    @test.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-actions:reset_network")
    @decorators.idempotent_id('2911a242-15c4-4fcb-80d5-80a8930661b0')
    def test_reset_network(self):
        """Test reset network, part of os-admin-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.reset_network(self.server_id)

    @testtools.skipUnless(CONF.compute_feature_enabled.change_password,
                          'Change password not available.')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-password")
    @decorators.idempotent_id('908a7d59-3a66-441c-94cf-38e57ed14956')
    def test_change_server_password(self):
        """Test change admin password, part of os-admin-password."""
        original_password = self.servers_client.show_password(self.server_id)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.change_password(
            self.server_id, adminPass=data_utils.rand_password())
        self.addCleanup(self.servers_client.change_password, self.server_id,
                        adminPass=original_password)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')

    @test.requires_ext(extension='os-deferred-delete', service='compute')
    @decorators.idempotent_id('189bfed4-1e6d-475c-bb8c-d57e60895391')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-deferred-delete")
    def test_force_delete_server(self):
        """Test force delete server, part of os-deferred-delete."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Force-deleting a server enforces os-deferred-delete.
        self.servers_client.force_delete_server(self.server_id)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:lock")
    @decorators.idempotent_id('b81e10fb-1864-498f-8c1d-5175c6fec5fb')
    def test_lock_server(self):
        """Test lock server, part of os-lock-server."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.lock_server(self.server_id)
        self.addCleanup(self.servers_client.unlock_server, self.server_id)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:unlock")
    @decorators.idempotent_id('d50ef8e8-4bce-11e7-b114-b2f933d5fe66')
    def test_unlock_server(self):
        """Test unlock server, part of os-lock-server."""
        self.servers_client.lock_server(self.server_id)
        self.addCleanup(self.servers_client.unlock_server, self.server_id)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.unlock_server(self.server_id)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:unlock:unlock_override")
    @decorators.idempotent_id('40dfeef9-73ee-48a9-be19-a219875de457')
    def test_unlock_server_override(self):
        """Test force unlock server, part of os-lock-server.

        In order to trigger the unlock:unlock_override policy instead
        of the unlock policy, the server must be locked by a different
        user than the one who is attempting to unlock it.
        """
        self.os_admin.servers_client.lock_server(self.server_id)
        self.addCleanup(self.servers_client.unlock_server, self.server_id)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.unlock_server(self.server_id)

    @test.requires_ext(extension='os-rescue', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-rescue")
    @decorators.idempotent_id('fbbb2afc-ed0e-4552-887d-ac00fb5d436e')
    def test_rescue_server(self):
        """Test rescue server, part of os-rescue."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.rescue_server(self.server_id)

    @test.requires_ext(extension='os-server-diagnostics', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-diagnostics")
    @decorators.idempotent_id('5dabfcc4-bedb-417b-8247-b3ee7c5c0f3e')
    def test_show_server_diagnostics(self):
        """Test show server diagnostics, part of os-server-diagnostics."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_server_diagnostics(self.server_id)

    @test.requires_ext(extension='os-server-password', service='compute')
    @decorators.idempotent_id('aaf43f78-c178-4581-ac18-14afd3f1f6ba')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-password")
    def test_delete_server_password(self):
        """Test delete server password, part of os-server-password."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.delete_password(self.server_id)

    @test.requires_ext(extension='os-server-password', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-password")
    @decorators.idempotent_id('f677971a-7d20-493c-977f-6ff0a74b5b2c')
    def test_get_server_password(self):
        """Test show server password, part of os-server-password."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_password(self.server_id)

    @test.requires_ext(extension='OS-SRV-USG', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-usage")
    @decorators.idempotent_id('f0437ead-b9fb-462a-9f3d-ce53fac9d57a')
    def test_show_server_usage(self):
        """Test show server usage, part of os-server-usage.

        TODO(felipemonteiro): Once multiple policy testing is supported, this
        test can be combined with the generic test for showing a server.
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_server(self.server_id)

    @test.requires_ext(extension='os-simple-tenant-usage', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-simple-tenant-usage:list")
    @decorators.idempotent_id('2aef094f-0452-4df6-a66a-0ec22a92b16e')
    def test_list_simple_tenant_usages(self):
        """Test list tenant usages, part of os-simple-tenant-usage."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.tenant_usages_client.list_tenant_usages()

    @test.requires_ext(extension='os-simple-tenant-usage', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-simple-tenant-usage:show")
    @decorators.idempotent_id('fe7eacda-15c4-4bf7-93ef-1091c4546a9d')
    def test_show_simple_tenant_usage(self):
        """Test show tenant usage, part of os-simple-tenant-usage."""
        tenant_id = self.auth_provider.credentials.tenant_id

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.tenant_usages_client.show_tenant_usage(tenant_id=tenant_id)

    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          "Suspend compute feature is not available.")
    @decorators.idempotent_id('b775930f-237c-431c-83ae-d33ed1b9700b')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-suspend-server:suspend")
    def test_suspend_server(self):
        """Test suspend server, part of os-suspend-server."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.suspend_server(self.server_id)
        self.addCleanup(self.servers_client.resume_server, self.server_id)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'SUSPENDED')

    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          "Suspend compute feature is not available.")
    @decorators.idempotent_id('4d90bd02-11f8-45b1-a8a1-534665584675')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-suspend-server:resume")
    def test_resume_server(self):
        """Test resume server, part of os-suspend-server."""
        self.servers_client.suspend_server(self.server_id)
        waiters.wait_for_server_status(self.servers_client, self.server_id,
                                       'SUSPENDED')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.resume_server(self.server_id)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server_id, 'ACTIVE')
