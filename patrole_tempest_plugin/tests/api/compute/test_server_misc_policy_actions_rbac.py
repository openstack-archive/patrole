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

import netaddr

import testtools

from tempest.common import utils
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF

if CONF.policy_feature_enabled.changed_nova_policies_ussuri:
    _DEFERRED_FORCE = "os_compute_api:os-deferred-delete:force"
    _ATTACH_INTERFACES_LIST = "os_compute_api:os-attach-interfaces:list"
    _ATTACH_INTERFACES_SHOW = "os_compute_api:os-attach-interfaces:show"
    _INSTANCE_ACTIONS_LIST = "os_compute_api:os-instance-actions:list"
    _SERVER_PASSWORD_SHOW = "os_compute_api:os-server-password:show"
    _SERVER_PASSWORD_CLEAR = "os_compute_api:os-server-password:clear"
else:
    _DEFERRED_FORCE = "os_compute_api:os-deferred-delete"
    _ATTACH_INTERFACES_LIST = "os_compute_api:os-attach-interfaces"
    _ATTACH_INTERFACES_SHOW = "os_compute_api:os-attach-interfaces"
    _INSTANCE_ACTIONS_LIST = "os_compute_api:os-instance-actions"
    _SERVER_PASSWORD_SHOW = "os_compute_api:os-server-password"
    _SERVER_PASSWORD_CLEAR = "os_compute_api:os-server-password"

if CONF.policy_feature_enabled.changed_nova_policies_victoria:
    _MULTINIC_ADD = "os_compute_api:os-multinic:add"
else:
    _MULTINIC_ADD = "os_compute_api:os-multinic"


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

    Tests are ordered by policy name.
    """

    credentials = ['primary', 'admin']

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources(network=True, subnet=True, router=True)
        super(MiscPolicyActionsRbacTest, cls).setup_credentials()

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

    @utils.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-admin-actions:reset_state"])
    @decorators.idempotent_id('ae84dd0b-f364-462e-b565-3457f9c019ef')
    def test_reset_server_state(self):
        """Test reset server state, part of os-admin-actions."""
        with self.override_role():
            self.servers_client.reset_state(self.server['id'], state='error')
        self.addCleanup(self.servers_client.reset_state, self.server['id'],
                        state='active')

    @utils.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-admin-actions:inject_network_info"])
    @decorators.idempotent_id('ce48c340-51c1-4cff-9b6e-0cc5ef008630')
    def test_inject_network_info(self):
        """Test inject network info, part of os-admin-actions."""
        with self.override_role():
            self.servers_client.inject_network_info(self.server['id'])

    @testtools.skipIf(
        CONF.policy_feature_enabled.removed_nova_policies_wallaby,
        "This API extension policy was removed in Wallaby")
    @utils.requires_ext(extension='os-admin-actions', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-admin-actions:reset_network"])
    @decorators.idempotent_id('2911a242-15c4-4fcb-80d5-80a8930661b0')
    def test_reset_network(self):
        """Test reset network, part of os-admin-actions."""
        with self.override_role():
            self.servers_client.reset_network(self.server['id'])

    @testtools.skipUnless(CONF.compute_feature_enabled.change_password,
                          'Change password not available.')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-admin-password"])
    @decorators.idempotent_id('908a7d59-3a66-441c-94cf-38e57ed14956')
    def test_change_server_password(self):
        """Test change admin password, part of os-admin-password."""
        original_password = self.servers_client.show_password(
            self.server['id'])

        with self.override_role():
            self.servers_client.change_password(
                self.server['id'], adminPass=data_utils.rand_password())
        self.addCleanup(self.servers_client.change_password, self.server['id'],
                        adminPass=original_password)
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'ACTIVE')

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @utils.requires_ext(extension='os-config-drive', service='compute')
    @decorators.idempotent_id('2c82e819-382d-4d6f-87f0-a45954cbbc64')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-config-drive"])
    def test_list_servers_with_details_config_drive(self):
        """Test list servers with config_drive property in response body."""
        with self.override_role():
            body = self.servers_client.list_servers(detail=True)['servers']
        expected_attr = 'config_drive'
        # If the first server contains "config_drive", then all the others do.
        if expected_attr not in body[0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @utils.requires_ext(extension='os-config-drive', service='compute')
    @decorators.idempotent_id('55c62ef7-b72b-4970-acc6-05b0a4316e5d')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-config-drive"])
    def test_show_server_config_drive(self):
        """Test show server with config_drive property in response body."""
        with self.override_role():
            body = self.servers_client.show_server(self.server['id'])['server']
        expected_attr = 'config_drive'
        if expected_attr not in body:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @utils.requires_ext(extension='os-deferred-delete', service='compute')
    @decorators.idempotent_id('189bfed4-1e6d-475c-bb8c-d57e60895391')
    @rbac_rule_validation.action(
        service="nova",
        rules=[_DEFERRED_FORCE])
    def test_force_delete_server(self):
        """Test force delete server, part of os-deferred-delete."""
        with self.override_role():
            # Force-deleting a server enforces os-deferred-delete.
            self.servers_client.force_delete_server(self.server['id'])

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('d873740a-7b10-40a9-943d-7cc18115370e')
    @utils.requires_ext(extension='OS-EXT-AZ', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-availability-zone"])
    def test_list_servers_with_details_extended_availability_zone(self):
        """Test list servers OS-EXT-AZ:availability_zone attr in resp body."""
        expected_attr = 'OS-EXT-AZ:availability_zone'

        with self.override_role():
            body = self.servers_client.list_servers(detail=True)['servers']
        # If the first server contains `expected_attr`, then all the others do.
        if expected_attr not in body[0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('727e5360-770a-4b9c-8015-513a40216635')
    @utils.requires_ext(extension='OS-EXT-AZ', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-availability-zone"])
    def test_show_server_extended_availability_zone(self):
        """Test show server OS-EXT-AZ:availability_zone attr in resp body."""
        expected_attr = 'OS-EXT-AZ:availability_zone'

        with self.override_role():
            body = self.servers_client.show_server(self.server['id'])['server']
        if expected_attr not in body:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('4aa5d93e-4887-468a-8eb4-b6eca0ca6437')
    @utils.requires_ext(extension='OS-EXT-SRV-ATTR', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-server-attributes"])
    def test_list_servers_extended_server_attributes(self):
        """Test list servers with details, with extended server attributes in
        response body.
        """
        with self.override_role():
            body = self.servers_client.list_servers(detail=True)['servers']

        # NOTE(felipemonteiro): The attributes included below should be
        # returned by all microversions. We don't include tests for other
        # microversions since Tempest schema validation takes care of that in
        # `show_server` call above. (Attributes there are *optional*.)
        for attr in ('host', 'instance_name'):
            whole_attr = 'OS-EXT-SRV-ATTR:%s' % attr
            if whole_attr not in body[0]:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=whole_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('2ed7aee2-94b2-4a9f-ae63-a51b7f94fe30')
    @utils.requires_ext(extension='OS-EXT-SRV-ATTR', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-server-attributes"])
    def test_show_server_extended_server_attributes(self):
        """Test show server with extended server attributes in response
        body.
        """
        with self.override_role():
            body = self.servers_client.show_server(self.server['id'])['server']

        # NOTE(felipemonteiro): The attributes included below should be
        # returned by all microversions. We don't include tests for other
        # microversions since Tempest schema validation takes care of that in
        # `show_server` call above. (Attributes there are *optional*.)
        for attr in ('host', 'instance_name'):
            whole_attr = 'OS-EXT-SRV-ATTR:%s' % attr
            if whole_attr not in body:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=whole_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('82053c27-3134-4003-9b55-bc9fafdb0e3b')
    @utils.requires_ext(extension='OS-EXT-STS', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-status"])
    def test_list_servers_extended_status(self):
        """Test list servers with extended properties in response body."""
        with self.override_role():
            body = self.servers_client.list_servers(detail=True)['servers']

        expected_attrs = ('OS-EXT-STS:task_state', 'OS-EXT-STS:vm_state',
                          'OS-EXT-STS:power_state')
        for attr in expected_attrs:
            if attr not in body[0]:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('7d2620a5-eea1-4a8b-96ea-86ad77a73fc8')
    @utils.requires_ext(extension='OS-EXT-STS', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-status"])
    def test_show_server_extended_status(self):
        """Test show server with extended properties in response body."""
        with self.override_role():
            body = self.servers_client.show_server(self.server['id'])['server']

        expected_attrs = ('OS-EXT-STS:task_state', 'OS-EXT-STS:vm_state',
                          'OS-EXT-STS:power_state')
        for attr in expected_attrs:
            if attr not in body:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('21e39cbe-6c32-48fc-80dd-3e1fece6053f')
    @utils.requires_ext(extension='os-extended-volumes', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-volumes"])
    def test_list_servers_with_details_extended_volumes(self):
        """Test list servers os-extended-volumes:volumes_attached attr in resp
        body.
        """
        expected_attr = 'os-extended-volumes:volumes_attached'

        with self.override_role():
            body = self.servers_client.list_servers(detail=True)['servers']
        if expected_attr not in body[0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @decorators.idempotent_id('7f163708-0d25-4138-8512-dfdd72a92989')
    @utils.requires_ext(extension='os-extended-volumes', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-extended-volumes"])
    def test_show_server_extended_volumes(self):
        """Test show server os-extended-volumes:volumes_attached attr in resp
        body.
        """
        expected_attr = 'os-extended-volumes:volumes_attached'

        with self.override_role():
            body = self.servers_client.show_server(self.server['id'])['server']
        if expected_attr not in body:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute=expected_attr)

    @utils.requires_ext(extension='os-instance-actions', service='compute')
    @decorators.idempotent_id('9d1b131d-407e-4fa3-8eef-eb2c4526f1da')
    @rbac_rule_validation.action(
        service="nova",
        rules=[_INSTANCE_ACTIONS_LIST])
    def test_list_instance_actions(self):
        """Test list instance actions, part of os-instance-actions."""
        with self.override_role():
            self.servers_client.list_instance_actions(self.server['id'])

    @utils.requires_ext(extension='os-instance-actions', service='compute')
    @decorators.idempotent_id('eb04c439-4215-4029-9ccb-5b3c041bfc25')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-instance-actions:events"])
    def test_show_instance_action(self):
        """Test show instance action, part of os-instance-actions.

        Expect "events" details to be included in the response body.
        """
        # NOTE: "os_compute_api:os-instance-actions" is also enforced.
        request_id = self.server.response['x-compute-request-id']

        with self.override_role():
            instance_action = self.servers_client.show_instance_action(
                self.server['id'], request_id)['instanceAction']

        if 'events' not in instance_action:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute='events')
        # Microversion 2.51+ returns 'events' always, but not 'traceback'. If
        # 'traceback' is also present then policy enforcement passed.
        if 'traceback' not in instance_action['events'][0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute='events.traceback')

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-keypairs"])
    @decorators.idempotent_id('81e6fa34-c06b-42ca-b195-82bf8699b940')
    def test_show_server_keypair(self):
        with self.override_role():
            result = self.servers_client.show_server(self.server['id'])[
                'server']
        if 'key_name' not in result:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute='key_name')

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-keypairs"])
    @decorators.idempotent_id('41ca4280-ec59-4b80-a9b1-6bc6366faf39')
    def test_list_servers_keypairs(self):
        with self.override_role():
            result = self.servers_client.list_servers(detail=True)['servers']
        if 'key_name' not in result[0]:
            raise rbac_exceptions.RbacMissingAttributeResponseBody(
                attribute='key_name')

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-lock-server:lock"])
    @decorators.idempotent_id('b81e10fb-1864-498f-8c1d-5175c6fec5fb')
    def test_lock_server(self):
        """Test lock server, part of os-lock-server."""
        with self.override_role():
            self.servers_client.lock_server(self.server['id'])
        self.addCleanup(self.servers_client.unlock_server, self.server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-lock-server:unlock"])
    @decorators.idempotent_id('d50ef8e8-4bce-11e7-b114-b2f933d5fe66')
    def test_unlock_server(self):
        """Test unlock server, part of os-lock-server."""
        self.servers_client.lock_server(self.server['id'])
        self.addCleanup(self.servers_client.unlock_server, self.server['id'])

        with self.override_role():
            self.servers_client.unlock_server(self.server['id'])

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-lock-server:unlock",
               "os_compute_api:os-lock-server:unlock:unlock_override"])
    @decorators.idempotent_id('40dfeef9-73ee-48a9-be19-a219875de457')
    def test_unlock_server_override(self):
        """Test force unlock server, part of os-lock-server.

        In order to trigger the unlock:unlock_override policy instead
        of the unlock policy, the server must be locked by a different
        user than the one who is attempting to unlock it.
        """
        self.os_admin.servers_client.lock_server(self.server['id'])
        self.addCleanup(self.servers_client.unlock_server, self.server['id'])

        with self.override_role():
            self.servers_client.unlock_server(self.server['id'])

    @utils.requires_ext(extension='os-rescue', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-rescue"])
    @decorators.idempotent_id('fbbb2afc-ed0e-4552-887d-ac00fb5d436e')
    def test_rescue_server(self):
        """Test rescue server, part of os-rescue."""
        with self.override_role():
            self.servers_client.rescue_server(self.server['id'])
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'RESCUE')

    @decorators.idempotent_id('ac2d956f-d6a3-4184-b814-b44d05c9574c')
    @utils.requires_ext(extension='os-rescue', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-rescue"])
    def test_unrescue_server(self):
        """Test unrescue server, part of os-rescue."""
        self.servers_client.rescue_server(self.server['id'])
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'RESCUE')

        with self.override_role():
            self.servers_client.unrescue_server(self.server['id'])
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'ACTIVE')

    @utils.requires_ext(extension='os-server-diagnostics', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-diagnostics"])
    @decorators.idempotent_id('5dabfcc4-bedb-417b-8247-b3ee7c5c0f3e')
    def test_show_server_diagnostics(self):
        """Test show server diagnostics, part of os-server-diagnostics."""
        with self.override_role():
            self.servers_client.show_server_diagnostics(self.server['id'])

    @utils.requires_ext(extension='os-server-password', service='compute')
    @decorators.idempotent_id('aaf43f78-c178-4581-ac18-14afd3f1f6ba')
    @rbac_rule_validation.action(
        service="nova",
        rules=[_SERVER_PASSWORD_CLEAR])
    def test_delete_server_password(self):
        """Test delete server password, part of os-server-password."""
        with self.override_role():
            self.servers_client.delete_password(self.server['id'])

    @utils.requires_ext(extension='os-server-password', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=[_SERVER_PASSWORD_SHOW])
    @decorators.idempotent_id('f677971a-7d20-493c-977f-6ff0a74b5b2c')
    def test_get_server_password(self):
        """Test show server password, part of os-server-password."""
        with self.override_role():
            self.servers_client.show_password(self.server['id'])

    @testtools.skipIf(CONF.policy_feature_enabled.removed_nova_policies_stein,
                      "This API extension policy was removed in Stein")
    @utils.requires_ext(extension='OS-SRV-USG', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-server-usage"])
    @decorators.idempotent_id('f0437ead-b9fb-462a-9f3d-ce53fac9d57a')
    def test_show_server_usage(self):
        """Test show server usage, part of os-server-usage.

        TODO(felipemonteiro): Once multiple policy testing is supported, this
        test should also check for additional policies mentioned here:
        https://git.openstack.org/cgit/openstack/nova/tree/nova/policies/server_usage.py?h=17.0.0
        """
        expected_attrs = ('OS-SRV-USG:launched_at',
                          'OS-SRV-USG:terminated_at')

        with self.override_role():
            body = self.servers_client.show_server(self.server['id'])['server']
        for expected_attr in expected_attrs:
            if expected_attr not in body:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=expected_attr)

    @utils.requires_ext(extension='os-simple-tenant-usage', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-simple-tenant-usage:list"])
    @decorators.idempotent_id('2aef094f-0452-4df6-a66a-0ec22a92b16e')
    def test_list_simple_tenant_usages(self):
        """Test list tenant usages, part of os-simple-tenant-usage."""
        with self.override_role():
            self.tenant_usages_client.list_tenant_usages()

    @utils.requires_ext(extension='os-simple-tenant-usage', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-simple-tenant-usage:show"])
    @decorators.idempotent_id('fe7eacda-15c4-4bf7-93ef-1091c4546a9d')
    def test_show_simple_tenant_usage(self):
        """Test show tenant usage, part of os-simple-tenant-usage."""
        tenant_id = self.os_primary.credentials.tenant_id

        with self.override_role():
            self.tenant_usages_client.show_tenant_usage(tenant_id=tenant_id)

    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          "Suspend compute feature is not available.")
    @decorators.idempotent_id('b775930f-237c-431c-83ae-d33ed1b9700b')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-suspend-server:suspend"])
    def test_suspend_server(self):
        """Test suspend server, part of os-suspend-server."""
        with self.override_role():
            self.servers_client.suspend_server(self.server['id'])
        self.addCleanup(self.servers_client.resume_server, self.server['id'])
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'SUSPENDED')

    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          "Suspend compute feature is not available.")
    @decorators.idempotent_id('4d90bd02-11f8-45b1-a8a1-534665584675')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-suspend-server:resume"])
    def test_resume_server(self):
        """Test resume server, part of os-suspend-server."""
        self.servers_client.suspend_server(self.server['id'])
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'SUSPENDED')

        with self.override_role():
            self.servers_client.resume_server(self.server['id'])
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'ACTIVE')


class MiscPolicyActionsNetworkRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """Test multiple policy actions that require a server to be created.

    Only applies to:
      * policy "families" that require server creation
      * small policy "families" -- i.e. containing one to three policies
      * tests that require network resources
    """

    @classmethod
    def skip_checks(cls):
        super(MiscPolicyActionsNetworkRbacTest, cls).skip_checks()
        # All tests below require Neutron availability.
        if not CONF.service_available.neutron:
            raise cls.skipException(
                '%s skipped as Neutron is required' % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(MiscPolicyActionsNetworkRbacTest, cls).setup_clients()
        cls.servers_admin_client = cls.os_admin.servers_client

    @classmethod
    def setup_credentials(cls):
        cls.prepare_instance_network()
        super(MiscPolicyActionsNetworkRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        def _cleanup_ports(network_id):
            ports = cls.ports_client.list_ports(network_id=network_id)['ports']
            for port in ports:
                test_utils.call_and_ignore_notfound_exc(
                    cls.ports_client.delete_port,
                    port['id'])

        super(MiscPolicyActionsNetworkRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

        # Create network the interface will be attached to
        network_name = data_utils.rand_name(cls.__name__ + '-network')
        post_body = {'name': network_name}
        post_body['router:external'] = False
        post_body['shared'] = True
        post_body['port_security_enabled'] = True
        cls.network = \
            cls.networks_client.create_network(**post_body)['network']
        cls.addClassResourceCleanup(
            cls.networks_client.delete_network,
            cls.network['id'])

        # Create subnet for network
        cls.cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
        cls.subnet = cls.subnets_client.create_subnet(
            network_id=cls.network['id'],
            cidr=cls.cidr,
            ip_version=4)['subnet']
        cls.addClassResourceCleanup(
            cls.subnets_client.delete_subnet,
            cls.subnet['id'])

        # ports on the network need to be deleted before the network can
        # be deleted
        cls.addClassResourceCleanup(_cleanup_ports, cls.network['id'])

    def _delete_and_wait_for_interface_detach(
            self, server_id, port_id):
        req_id = self.interfaces_client.delete_interface(
            server_id, port_id
        ).response['x-openstack-request-id']
        waiters.wait_for_interface_detach(
            self.servers_admin_client, server_id, port_id, req_id)

    def _delete_and_wait_for_interface_detach_ignore_timeout(
            self, server_id, port_id):
        try:
            self._delete_and_wait_for_interface_detach(
                server_id, port_id)
        except lib_exc.TimeoutException:
            pass

    def _attach_interface_to_server(self):
        network_id = self.network['id']
        interface = self.interfaces_client.create_interface(
            self.server['id'], net_id=network_id)['interfaceAttachment']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self._delete_and_wait_for_interface_detach_ignore_timeout,
            self.server['id'], interface['port_id'])
        waiters.wait_for_interface_status(
            self.interfaces_client, self.server['id'],
            interface['port_id'], 'ACTIVE')
        return interface

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @utils.requires_ext(extension='os-attach-interfaces', service='compute')
    @decorators.idempotent_id('ddf53cb6-4a0a-4e5a-91e3-6c32aaa3b9b6')
    @rbac_rule_validation.action(
        service="nova",
        rules=[_ATTACH_INTERFACES_LIST])
    def test_list_interfaces(self):
        """Test list interfaces, part of os-attach-interfaces."""
        with self.override_role():
            self.interfaces_client.list_interfaces(self.server['id'])

    @decorators.idempotent_id('1b9cf7db-dc50-48a2-8eb9-8c25af5e934a')
    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @utils.requires_ext(extension='os-attach-interfaces', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=[_ATTACH_INTERFACES_SHOW])
    def test_show_interface(self):
        """Test show interfaces, part of os-attach-interfaces."""
        interface = self._attach_interface_to_server()
        with self.override_role():
            self.interfaces_client.show_interface(
                self.server['id'], interface['port_id'])

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @utils.requires_ext(extension='os-attach-interfaces', service='compute')
    @decorators.idempotent_id('d2d3a24d-4738-4bce-a287-36d664746cde')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-attach-interfaces:create"])
    def test_create_interface(self):
        """Test create interface, part of os-attach-interfaces."""
        network_id = self.network['id']
        with self.override_role():
            interface = self.interfaces_client.create_interface(
                self.server['id'], net_id=network_id)['interfaceAttachment']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self._delete_and_wait_for_interface_detach_ignore_timeout,
            self.server['id'], interface['port_id'])
        waiters.wait_for_interface_status(
            self.interfaces_client, self.server['id'],
            interface['port_id'], 'ACTIVE')

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @utils.requires_ext(extension='os-attach-interfaces', service='compute')
    @decorators.idempotent_id('55b05692-ed44-4608-a84c-cd4219c82799')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-attach-interfaces:delete"])
    def test_delete_interface(self):
        """Test delete interface, part of os-attach-interfaces."""
        interface = self._attach_interface_to_server()

        with self.override_role():
            req_id = self.interfaces_client.delete_interface(
                self.server['id'], interface['port_id'])
        try:
            # interface may be not found - we need to ignore that
            waiters.wait_for_interface_detach(
                self.servers_admin_client, self.server['id'],
                interface['port_id'], req_id)
        except lib_exc.NotFound:
            pass

    @decorators.idempotent_id('6886d360-0d86-4760-b1a3-882d81fbebcc')
    @utils.requires_ext(extension='os-ips', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:ips:index"])
    def test_list_addresses(self):
        """Test list server addresses, part of ips policy family."""
        with self.override_role():
            self.servers_client.list_addresses(self.server['id'])

    @decorators.idempotent_id('fa43e7e5-0db9-48eb-9c6b-c11eb766b8e4')
    @utils.requires_ext(extension='os-ips', service='compute')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:ips:show"])
    def test_list_addresses_by_network(self):
        """Test list server addresses by network, part of ips policy family."""
        addresses = self.servers_client.list_addresses(self.server['id'])[
            'addresses']
        address = next(iter(addresses))

        with self.override_role():
            self.servers_client.list_addresses_by_network(
                self.server['id'], address)

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          "Interface attachment is not available.")
    @utils.requires_ext(extension='os-multinic', service='compute')
    @rbac_rule_validation.action(
        service="nova", rules=[_MULTINIC_ADD])
    @decorators.idempotent_id('bd3e2c74-130a-40f0-8085-124d93fe67da')
    def test_add_fixed_ip(self):
        """Test add fixed ip to server network, part of os-multinic."""
        interfaces = (self.interfaces_client.list_interfaces(self.server['id'])
                      ['interfaceAttachments'])
        if interfaces:
            network_id = interfaces[0]['net_id']
        else:
            interface = self.interfaces_client.create_interface(
                self.server['id'])['interfaceAttachment']
            network_id = interface['net_id']
            self.addCleanup(
                self._delete_and_wait_for_interface_detach,
                self.server['id'], interface['port_id'])

        with self.override_role():
            self.servers_client.add_fixed_ip(self.server['id'],
                                             networkId=network_id)
        # Get the Fixed IP from server.
        server_detail = self.servers_client.show_server(
            self.server['id'])['server']
        fixed_ip = None
        for ip_set in server_detail['addresses']:
            for ip in server_detail['addresses'][ip_set]:
                if ip['OS-EXT-IPS:type'] == 'fixed':
                    fixed_ip = ip['addr']
                    break
            if fixed_ip is not None:
                break
        # Remove the fixed IP from server.
        # TODO(gmann): separate the remve fixded ip test as it has
        # separate policy now.
        # self.servers_client.remove_fixed_ip(self.server['id'],
        #                                    address=fixed_ip)
