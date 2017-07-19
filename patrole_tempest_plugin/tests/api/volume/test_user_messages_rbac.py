# Copyright 2017 AT&T Corporation.
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class MessagesV3RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3
    min_microversion = '3.3'
    max_microversion = 'latest'

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(MessagesV3RbacTest, cls).setup_clients()
        cls.messages_client = cls.os_primary.volume_v3_messages_client
        cls.admin_messages_client = cls.os_admin.volume_v3_messages_client

    def _create_user_message(self):
        """Trigger a 'no valid host' situation to generate a message."""
        bad_protocol = data_utils.rand_name(
            self.__class__.__name__ + '-storage_protocol')
        bad_vendor = data_utils.rand_name(
            self.__class__.__name__ + '-vendor_name')
        extra_specs = {'storage_protocol': bad_protocol,
                       'vendor_name': bad_vendor}
        vol_type_name = data_utils.rand_name(
            self.__class__.__name__ + '-volume-type')
        bogus_type = self.create_volume_type(
            name=vol_type_name, extra_specs=extra_specs)
        params = {'volume_type': bogus_type['id'],
                  'size': CONF.volume.volume_size}
        volume = self.create_volume(wait_until="error", **params)
        messages = self.messages_client.list_messages()['messages']
        message_id = None
        for message in messages:
            if message['resource_uuid'] == volume['id']:
                message_id = message['id']
                break
        self.assertIsNotNone(message_id, 'No user message generated for '
                                         'volume %s' % volume['id'])

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.messages_client.delete_message, message_id)

        return message_id

    @decorators.idempotent_id('bf7f31a1-509b-4a7d-a8a8-ad6ce68229c7')
    @rbac_rule_validation.action(
        service="cinder",
        rule="message:get_all")
    def test_list_messages(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.messages_client.list_messages()['messages']

    @decorators.idempotent_id('9cc1ad1e-68a2-4407-8b60-ea77909bce08')
    @rbac_rule_validation.action(
        service="cinder",
        rule="message:get")
    def test_show_message(self):
        message_id = self._create_user_message()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.messages_client.show_message(message_id)['message']

    @decorators.idempotent_id('65ca7fb7-7f2c-443e-b144-ac86973a97be')
    @rbac_rule_validation.action(
        service="cinder",
        rule="message:delete")
    def test_delete_message(self):
        message_id = self._create_user_message()

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.messages_client.delete_message(message_id)
        self.admin_messages_client.wait_for_resource_deletion(message_id)
