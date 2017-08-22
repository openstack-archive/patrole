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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from patrole_tempest_plugin import rbac_exceptions
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

    credentials = ['primary', 'admin']

    @classmethod
    def resource_setup(cls):
        super(MiscPolicyActionsRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    def setUp(self):
        super(MiscPolicyActionsRbacTest, self).setUp()
        try:
            waiters.wait_for_server_status(self.servers_client,
                                           self.server['id'], 'ACTIVE')
        except lib_exc.NotFound:
            # If the server was found to be deleted by a previous test,
            # a new one is built
            self.__class__.server = self.create_test_server(
                wait_until='ACTIVE')
        except Exception:
            # Rebuilding the server in case something happened during a test
            self.__class__.server = self._rebuild_server(self.server['id'])

    def _rebuild_server(self, server_id):
        # Destroy an existing server and creates a new one.
        if server_id:
            self.delete_server(server_id)

        self.password = data_utils.rand_password()
        return self.create_test_server(
            wait_until='ACTIVE', adminPass=self.password)

    @test.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-actions:reset_state")
    @decorators.idempotent_id('ae84dd0b-f364-462e-b565-3457f9c019ef')
    def test_reset_server_state(self):
        """Test reset server state, part of os-admin-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.reset_state(self.server['id'], state='error')
        self.addCleanup(self.servers_client.reset_state, self.server['id'],
                        state='active')

    @test.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-actions:inject_network_info")
    @decorators.idempotent_id('ce48c340-51c1-4cff-9b6e-0cc5ef008630')
    def test_inject_network_info(self):
        """Test inject network info, part of os-admin-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.inject_network_info(self.server['id'])

    @test.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-actions:reset_network")
    @decorators.idempotent_id('2911a242-15c4-4fcb-80d5-80a8930661b0')
    def test_reset_network(self):
        """Test reset network, part of os-admin-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.reset_network(self.server['id'])

    @testtools.skipUnless(CONF.compute_feature_enabled.change_password,
                          'Change password not available.')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-admin-password")
    @decorators.idempotent_id('908a7d59-3a66-441c-94cf-38e57ed14956')
    def test_change_server_password(self):
        """Test change admin password, part of os-admin-password."""
        original_password = self.servers_client.show_password(
            self.server['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.change_password(
            self.server['id'], adminPass=data_utils.rand_password())
        self.addCleanup(self.servers_client.change_password, self.server['id'],
                        adminPass=original_password)
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server['id'], 'ACTIVE')

    @test.requires_ext(extension='os-config-drive', service='compute')
    @decorators.idempotent_id('2c82e819-382d-4d6f-87f0-a45954cbbc64')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-config-drive")
    def test_list_servers_with_details_config_drive(self):
        """Test list servers with config_drive property in response body."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.servers_client.list_servers(detail=True)['servers']
        expected_attr = 'config_drive'
        # If the first server contains "config_drive", then all the others do.
        if expected_attr not in body[0]:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)

    @test.requires_ext(extension='os-config-drive', service='compute')
    @decorators.idempotent_id('55c62ef7-b72b-4970-acc6-05b0a4316e5d')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-config-drive")
    def test_show_server_config_drive(self):
        """Test show server with config_drive property in response body."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)

        body = self.servers_client.show_server(self.server['id'])['server']
        expected_attr = 'config_drive'
        if expected_attr not in body:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)

    @test.requires_ext(extension='os-deferred-delete', service='compute')
    @decorators.idempotent_id('189bfed4-1e6d-475c-bb8c-d57e60895391')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-deferred-delete")
    def test_force_delete_server(self):
        """Test force delete server, part of os-deferred-delete."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Force-deleting a server enforces os-deferred-delete.
        self.servers_client.force_delete_server(self.server['id'])

    @test.requires_ext(extension='os-instance-actions', service='compute')
    @decorators.idempotent_id('9d1b131d-407e-4fa3-8eef-eb2c4526f1da')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-instance-actions")
    def test_list_instance_actions(self):
        """Test list instance actions, part of os-instance-actions."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_instance_actions(self.server['id'])

    @test.requires_ext(extension='os-instance-actions', service='compute')
    @decorators.idempotent_id('eb04c439-4215-4029-9ccb-5b3c041bfc25')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-instance-actions:events")
    def test_show_instance_action(self):
        """Test show instance action, part of os-instance-actions.

        Expect "events" details to be included in the response body.
        """
        # NOTE: "os_compute_api:os-instance-actions" is also enforced.
        request_id = self.server.response['x-compute-request-id']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        instance_action = self.servers_client.show_instance_action(
            self.server['id'], request_id)['instanceAction']

        if 'events' not in instance_action:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute='events')
        # Microversion 2.51+ returns 'events' always, but not 'traceback'. If
        # 'traceback' is also present then policy enforcement passed.
        if 'traceback' not in instance_action['events'][0]:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute='events.traceback')

    @decorators.idempotent_id('82053c27-3134-4003-9b55-bc9fafdb0e3b')
    @test.requires_ext(extension='OS-EXT-STS', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-extended-status")
    def test_list_servers_extended_status(self):
        """Test list servers with extended properties in response body."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.servers_client.list_servers(detail=True)['servers']

        expected_attrs = ('OS-EXT-STS:task_state', 'OS-EXT-STS:vm_state',
                          'OS-EXT-STS:power_state')
        for attr in expected_attrs:
            if attr not in body[0]:
                raise rbac_exceptions.RbacMalformedResponse(
                    attribute=attr)

    @decorators.idempotent_id('7d2620a5-eea1-4a8b-96ea-86ad77a73fc8')
    @test.requires_ext(extension='OS-EXT-STS', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-extended-status")
    def test_show_server_extended_status(self):
        """Test show server with extended properties in response body."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.servers_client.show_server(self.server['id'])['server']

        expected_attrs = ('OS-EXT-STS:task_state', 'OS-EXT-STS:vm_state',
                          'OS-EXT-STS:power_state')
        for attr in expected_attrs:
            if attr not in body:
                raise rbac_exceptions.RbacMalformedResponse(
                    attribute=attr)

    @decorators.idempotent_id('d873740a-7b10-40a9-943d-7cc18115370e')
    @test.requires_ext(extension='OS-EXT-AZ', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-extended-availability-zone")
    def test_list_servers_with_details_extended_availability_zone(self):
        """Test list servers OS-EXT-AZ:availability_zone attr in resp body."""
        expected_attr = 'OS-EXT-AZ:availability_zone'

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.servers_client.list_servers(detail=True)['servers']
        # If the first server contains `expected_attr`, then all the others do.
        if expected_attr not in body[0]:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)

    @decorators.idempotent_id('727e5360-770a-4b9c-8015-513a40216635')
    @test.requires_ext(extension='OS-EXT-AZ', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-extended-availability-zone")
    def test_show_server_extended_availability_zone(self):
        """Test show server OS-EXT-AZ:availability_zone attr in resp body."""
        expected_attr = 'OS-EXT-AZ:availability_zone'

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        body = self.servers_client.show_server(self.server['id'])['server']
        if expected_attr not in body:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute=expected_attr)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:lock")
    @decorators.idempotent_id('b81e10fb-1864-498f-8c1d-5175c6fec5fb')
    def test_lock_server(self):
        """Test lock server, part of os-lock-server."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.lock_server(self.server['id'])
        self.addCleanup(self.servers_client.unlock_server, self.server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-lock-server:unlock")
    @decorators.idempotent_id('d50ef8e8-4bce-11e7-b114-b2f933d5fe66')
    def test_unlock_server(self):
        """Test unlock server, part of os-lock-server."""
        self.servers_client.lock_server(self.server['id'])
        self.addCleanup(self.servers_client.unlock_server, self.server['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.unlock_server(self.server['id'])

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
        self.os_admin.servers_client.lock_server(self.server['id'])
        self.addCleanup(self.servers_client.unlock_server, self.server['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.unlock_server(self.server['id'])

    @test.requires_ext(extension='os-rescue', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-rescue")
    @decorators.idempotent_id('fbbb2afc-ed0e-4552-887d-ac00fb5d436e')
    def test_rescue_server(self):
        """Test rescue server, part of os-rescue."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.rescue_server(self.server['id'])

    @test.requires_ext(extension='os-server-diagnostics', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-diagnostics")
    @decorators.idempotent_id('5dabfcc4-bedb-417b-8247-b3ee7c5c0f3e')
    def test_show_server_diagnostics(self):
        """Test show server diagnostics, part of os-server-diagnostics."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_server_diagnostics(self.server['id'])

    @test.requires_ext(extension='os-server-password', service='compute')
    @decorators.idempotent_id('aaf43f78-c178-4581-ac18-14afd3f1f6ba')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-password")
    def test_delete_server_password(self):
        """Test delete server password, part of os-server-password."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.delete_password(self.server['id'])

    @test.requires_ext(extension='os-server-password', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-server-password")
    @decorators.idempotent_id('f677971a-7d20-493c-977f-6ff0a74b5b2c')
    def test_get_server_password(self):
        """Test show server password, part of os-server-password."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.show_password(self.server['id'])

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
        self.servers_client.show_server(self.server['id'])

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
        tenant_id = self.os_primary.credentials.tenant_id

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
        self.servers_client.suspend_server(self.server['id'])
        self.addCleanup(self.servers_client.resume_server, self.server['id'])
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server['id'], 'SUSPENDED')

    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          "Suspend compute feature is not available.")
    @decorators.idempotent_id('4d90bd02-11f8-45b1-a8a1-534665584675')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-suspend-server:resume")
    def test_resume_server(self):
        """Test resume server, part of os-suspend-server."""
        self.servers_client.suspend_server(self.server['id'])
        waiters.wait_for_server_status(self.servers_client, self.server['id'],
                                       'SUSPENDED')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.resume_server(self.server['id'])
        waiters.wait_for_server_status(
            self.os_admin.servers_client, self.server['id'], 'ACTIVE')


class MiscPolicyActionsNetworkRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """Test multiple policy actions that require a server to be created.

    Only applies to:
      * policy "families" that require server creation
      * small policy "families" -- i.e. containing one to three policies
      * tests that require network resources
    """

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(MiscPolicyActionsNetworkRbacTest, cls).skip_checks()
        # All tests below require Neutron availability.
        if not CONF.service_available.neutron:
            raise cls.skipException(
                '%s skipped as Neutron is required' % cls.__name__)

    @classmethod
    def setup_credentials(cls):
        cls.prepare_instance_network()
        super(MiscPolicyActionsNetworkRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(MiscPolicyActionsNetworkRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    def _attach_interface_to_server(self):
        interface = self.interfaces_client.create_interface(
            self.server['id'])['interfaceAttachment']
        waiters.wait_for_interface_status(
            self.os_admin.interfaces_client, self.server['id'],
            interface['port_id'], 'ACTIVE')
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.interfaces_client.delete_interface,
            self.server['id'], interface['port_id'])
        return interface

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @test.requires_ext(extension='os-attach-interfaces', service='compute')
    @decorators.idempotent_id('ddf53cb6-4a0a-4e5a-91e3-6c32aaa3b9b6')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-attach-interfaces")
    def test_list_interfaces(self):
        """Test list interfaces, part of os-attach-interfaces."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.interfaces_client.list_interfaces(
            self.server['id'])['interfaceAttachments']

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @test.requires_ext(extension='os-attach-interfaces', service='compute')
    @decorators.idempotent_id('d2d3a24d-4738-4bce-a287-36d664746cde')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-attach-interfaces:create")
    def test_create_interface(self):
        """Test create interface, part of os-attach-interfaces."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._attach_interface_to_server()

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @test.requires_ext(extension='os-attach-interfaces', service='compute')
    @decorators.idempotent_id('55b05692-ed44-4608-a84c-cd4219c82799')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-attach-interfaces:delete")
    def test_delete_interface(self):
        """Test delete interface, part of os-attach-interfaces."""
        interface = self._attach_interface_to_server()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.interfaces_client.delete_interface(self.server['id'],
                                                interface['port_id'])

    @decorators.idempotent_id('6886d360-0d86-4760-b1a3-882d81fbebcc')
    @test.requires_ext(extension='os-ips', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:ips:index")
    def test_list_addresses(self):
        """Test list server addresses, part of ips policy family."""
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_addresses(self.server['id'])['addresses']

    @decorators.idempotent_id('fa43e7e5-0db9-48eb-9c6b-c11eb766b8e4')
    @test.requires_ext(extension='os-ips', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:ips:show")
    def test_list_addresses_by_network(self):
        """Test list server addresses by network, part of ips policy family."""
        addresses = self.servers_client.list_addresses(self.server['id'])[
            'addresses']
        address = next(iter(addresses))

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.list_addresses_by_network(
            self.server['id'], address)[address]

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @test.requires_ext(extension='os-multinic', service='compute')
    @rbac_rule_validation.action(
        service="nova", rule="os_compute_api:os-multinic")
    @decorators.idempotent_id('bd3e2c74-130a-40f0-8085-124d93fe67da')
    def test_add_fixed_ip(self):
        """Test add fixed ip to server network, part of os-multinic."""
        interfaces = (self.interfaces_client.list_interfaces(self.server['id'])
                      ['interfaceAttachments'])
        if interfaces:
            network_id = interfaces[0]['net_id']
        else:
            network_id = self.interfaces_client.create_interface(
                self.server['id'])['interfaceAttachment']['net_id']

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.servers_client.add_fixed_ip(self.server['id'],
                                         networkId=network_id)

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-virtual-interfaces")
    @decorators.idempotent_id('fc719ae3-0f73-4689-8378-1b841f0f2818')
    def test_list_virtual_interfaces(self):
        """Test list virtual interfaces, part of os-virtual-interfaces.

        If Neutron is available, then call the API and expect it to fail
        with a 400 BadRequest (policy enforcement is done before that happens).

        For more information, see:
        https://developer.openstack.org/api-ref/compute/#servers-virtual-interfaces-servers-os-virtual-interfaces-deprecated
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        if CONF.service_available.neutron:
            msg = "Listing virtual interfaces is not supported by this cloud."
            with self.assertRaisesRegex(lib_exc.BadRequest, msg):
                self.servers_client.list_virtual_interfaces(self.server['id'])
        else:
            self.servers_client.list_virtual_interfaces(self.server['id'])
