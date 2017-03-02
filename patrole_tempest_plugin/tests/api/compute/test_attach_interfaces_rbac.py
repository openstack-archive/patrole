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

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF


class AttachInterfacesRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(AttachInterfacesRbacTest, cls).setup_clients()
        cls.client = cls.interfaces_client

    @classmethod
    def skip_checks(cls):
        super(AttachInterfacesRbacTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)
        if not CONF.compute_feature_enabled.interface_attach:
            raise cls.skipException(
                "%s skipped as interface attachment is not available"
                % cls.__name__)
        if not CONF.service_available.neutron:
            raise cls.skipException(
                '%s skipped as Neutron is required' % cls.__name__)

    @classmethod
    def setup_credentials(cls):
        cls.prepare_instance_network()
        super(AttachInterfacesRbacTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(AttachInterfacesRbacTest, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(AttachInterfacesRbacTest, self).tearDown()

    def _attach_interface_to_server(self):
        interface = self.client.create_interface(
            self.server['id'])['interfaceAttachment']
        waiters.wait_for_interface_status(
            self.interfaces_client, self.server['id'], interface['port_id'],
            'ACTIVE')
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.client.delete_interface, self.server['id'],
            interface['port_id'])
        return interface

    @decorators.idempotent_id('ddf53cb6-4a0a-4e5a-91e3-6c32aaa3b9b6')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-attach-interfaces")
    def test_list_interfaces(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_interfaces(self.server['id'])['interfaceAttachments']

    @decorators.idempotent_id('d2d3a24d-4738-4bce-a287-36d664746cde')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-attach-interfaces:create")
    def test_create_interface(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._attach_interface_to_server()

    @decorators.idempotent_id('55b05692-ed44-4608-a84c-cd4219c82799')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-attach-interfaces:delete")
    def test_delete_interface(self):
        interface = self._attach_interface_to_server()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.delete_interface(self.server['id'], interface['port_id'])
