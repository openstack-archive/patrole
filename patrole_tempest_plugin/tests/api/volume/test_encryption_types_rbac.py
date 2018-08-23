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

import functools

from tempest.common import utils
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


def _get_volume_type_encryption_policy(action):
    feature_flag = CONF.policy_feature_enabled.added_cinder_policies_stein

    if feature_flag:
        return "volume_extension:volume_type_encryption:%s" % action

    return "volume_extension:volume_type_encryption"


_CREATE_VOLUME_TYPE_ENCRYPTION = functools.partial(
    _get_volume_type_encryption_policy, "create")
_SHOW_VOLUME_TYPE_ENCRYPTION = functools.partial(
    _get_volume_type_encryption_policy, "get")
_UPDATE_VOLUME_TYPE_ENCRYPTION = functools.partial(
    _get_volume_type_encryption_policy, "update")
_DELETE_VOLUME_TYPE_ENCRYPTION = functools.partial(
    _get_volume_type_encryption_policy, "delete")


class EncryptionTypesV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(EncryptionTypesV3RbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('encryption', 'volume'):
            msg = "%s skipped as encryption not enabled." % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(EncryptionTypesV3RbacTest, cls).setup_clients()
        cls.encryption_types_client = cls.os_primary.encryption_types_v2_client

    def _create_volume_type_encryption(self):
        vol_type_id = self.create_volume_type()['id']
        self.encryption_types_client.create_encryption_type(
            vol_type_id,
            provider="nova.volume.encryptors.luks.LuksEncryptor",
            control_location="front-end")['encryption']
        return vol_type_id

    @decorators.idempotent_id('ffd94ce5-c24b-4b6c-84c9-c5aad8c3010c')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_CREATE_VOLUME_TYPE_ENCRYPTION])
    def test_create_volume_type_encryption(self):
        vol_type_id = self.create_volume_type()['id']
        with self.rbac_utils.override_role(self):
            self.encryption_types_client.create_encryption_type(
                vol_type_id,
                provider="nova.volume.encryptors.luks.LuksEncryptor",
                control_location="front-end")['encryption']

    @decorators.idempotent_id('6599e72e-acef-4c0d-a9b2-463fca30d1da')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_DELETE_VOLUME_TYPE_ENCRYPTION])
    def test_delete_volume_type_encryption(self):
        vol_type_id = self._create_volume_type_encryption()
        with self.rbac_utils.override_role(self):
            self.encryption_types_client.delete_encryption_type(vol_type_id)

    @decorators.idempotent_id('42da9fec-32fd-4dca-9242-8a53b2fed25a')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_UPDATE_VOLUME_TYPE_ENCRYPTION])
    def test_update_volume_type_encryption(self):
        vol_type_id = self._create_volume_type_encryption()
        with self.rbac_utils.override_role(self):
            self.encryption_types_client.update_encryption_type(
                vol_type_id,
                control_location="front-end")

    @decorators.idempotent_id('1381a3dc-248f-4282-b231-c9399018c804')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_SHOW_VOLUME_TYPE_ENCRYPTION])
    def test_show_volume_type_encryption(self):
        vol_type_id = self._create_volume_type_encryption()
        with self.rbac_utils.override_role(self):
            self.encryption_types_client.show_encryption_type(vol_type_id)

    @decorators.idempotent_id('d4ed3cf8-52b2-4fa2-910d-e405361f0881')
    @rbac_rule_validation.action(
        service="cinder",
        rules=[_SHOW_VOLUME_TYPE_ENCRYPTION])
    def test_show_encryption_specs_item(self):
        vol_type_id = self._create_volume_type_encryption()
        with self.rbac_utils.override_role(self):
            self.encryption_types_client.show_encryption_specs_item(
                vol_type_id, 'provider')
