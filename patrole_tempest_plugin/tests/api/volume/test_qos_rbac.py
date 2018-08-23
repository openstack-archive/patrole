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

from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeQOSV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(VolumeQOSV3RbacTest, cls).setup_clients()
        cls.qos_client = cls.os_primary.volume_qos_v2_client

    def _create_test_qos_specs(self, name=None, consumer=None, **kwargs):
        name = name or data_utils.rand_name(self.__class__.__name__ + '-QoS')
        consumer = consumer or 'front-end'
        qos_specs = self.qos_client.create_qos(
            name=name, consumer=consumer, **kwargs)['qos_specs']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.qos_client.delete_qos, qos_specs['id'])
        return qos_specs

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:create"])
    @decorators.idempotent_id('4f9f45f0-b379-4577-a279-cec3e917cbec')
    def test_create_qos_with_consumer(self):
        with self.rbac_utils.override_role(self):
            self._create_test_qos_specs()

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:delete"])
    @decorators.idempotent_id('fbc8a77e-6b6d-45ae-bebe-c496eb8f06f7')
    def test_delete_qos_with_consumer(self):
        qos = self._create_test_qos_specs()
        with self.rbac_utils.override_role(self):
            self.qos_client.delete_qos(qos['id'])

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:qos_specs_manage:get"])
    @decorators.idempotent_id('22aff0dd-0343-408d-ae80-e77551956e14')
    def test_show_qos(self):
        qos = self._create_test_qos_specs()
        with self.rbac_utils.override_role(self):
            self.qos_client.show_qos(qos['id'])['qos_specs']

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:qos_specs_manage:get_all"])
    @decorators.idempotent_id('ff1e98f3-d456-40a9-96d4-c7e4a55dcffa')
    def test_get_association_qos(self):
        qos = self._create_test_qos_specs()
        vol_type = self.create_volume_type()['id']
        self.qos_client.associate_qos(qos['id'], vol_type)
        self.addCleanup(self.qos_client.disassociate_qos, qos['id'], vol_type)

        with self.rbac_utils.override_role(self):
            self.qos_client.show_association_qos(qos['id'])

    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:qos_specs_manage:get_all"])
    @decorators.idempotent_id('546b8bb1-04a4-4387-9506-a538a7f3cd6a')
    def test_list_qos(self):
        with self.rbac_utils.override_role(self):
            self.qos_client.list_qos()['qos_specs']

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:update"])
    @decorators.idempotent_id('89b630b7-c170-47c3-ac80-50ed425c2d98')
    def test_set_qos_key(self):
        qos = self._create_test_qos_specs()
        with self.rbac_utils.override_role(self):
            self.qos_client.set_qos_key(
                qos['id'], iops_bytes='500')['qos_specs']

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:update"])
    @decorators.idempotent_id('6c50c837-de77-4dae-a2ec-30e05c62969c')
    def test_unset_qos_key(self):
        qos = self._create_test_qos_specs()
        self.qos_client.set_qos_key(qos['id'], iops_bytes='500')['qos_specs']

        with self.rbac_utils.override_role(self):
            self.qos_client.unset_qos_key(qos['id'], ['iops_bytes'])
        waiters.wait_for_qos_operations(self.qos_client, qos['id'],
                                        'qos-key-unset', args=['iops_bytes'])

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:update"])
    @decorators.idempotent_id('2047b347-8bbe-405e-bf5a-c75a0d7e3930')
    def test_associate_qos(self):
        qos = self._create_test_qos_specs()
        vol_type = self.create_volume_type()['id']

        with self.rbac_utils.override_role(self):
            self.qos_client.associate_qos(qos['id'], vol_type)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.qos_client.disassociate_qos, qos['id'], vol_type)

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:update"])
    @decorators.idempotent_id('f12aeca1-0c02-4f33-b805-014171e5b2d4')
    def test_disassociate_qos(self):
        qos = self._create_test_qos_specs()
        vol_type = self.create_volume_type()['id']
        self.qos_client.associate_qos(qos['id'], vol_type)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.qos_client.disassociate_qos, qos['id'], vol_type)

        with self.rbac_utils.override_role(self):
            self.qos_client.disassociate_qos(qos['id'], vol_type)
        waiters.wait_for_qos_operations(self.qos_client, qos['id'],
                                        'disassociate', args=vol_type)

    @rbac_rule_validation.action(
        service="cinder", rules=["volume_extension:qos_specs_manage:update"])
    @decorators.idempotent_id('9f6e664d-a5d9-4e71-b122-73a3086be1b9')
    def test_disassociate_all_qos(self):
        qos = self._create_test_qos_specs()
        vol_type = self.create_volume_type()['id']
        self.qos_client.associate_qos(qos['id'], vol_type)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.qos_client.disassociate_qos, qos['id'], vol_type)

        with self.rbac_utils.override_role(self):
            self.qos_client.disassociate_all_qos(qos['id'])
        waiters.wait_for_qos_operations(self.qos_client, qos['id'],
                                        'disassociate-all')
