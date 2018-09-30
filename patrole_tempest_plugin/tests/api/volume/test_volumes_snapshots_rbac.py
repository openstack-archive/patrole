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
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class VolumesSnapshotV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(VolumesSnapshotV3RbacTest, cls).skip_checks()
        if not CONF.volume_feature_enabled.snapshot:
            raise cls.skipException("Cinder volume snapshots are disabled")

    @classmethod
    def resource_setup(cls):
        super(VolumesSnapshotV3RbacTest, cls).resource_setup()
        # Create a test shared volume for tests
        cls.volume = cls.create_volume()
        # Create a test shared snapshot for tests
        cls.snapshot = cls.create_snapshot(cls.volume['id'])

    def _list_by_param_values(self, with_detail=False, **params):
        # Perform list or list_details action with given params.
        return self.snapshots_client.list_snapshots(
            detail=with_detail, **params)['snapshots']

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:create_snapshot"])
    @decorators.idempotent_id('ac7b2ee5-fbc0-4360-afc2-de8fa4881ede')
    def test_create_snapshot(self):
        # Create a temp snapshot
        with self.rbac_utils.override_role(self):
            self.create_snapshot(self.volume['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_snapshot"])
    @decorators.idempotent_id('93a11b40-1ba8-44d6-a196-f8d97220f796')
    def test_show_snapshot(self):
        # Get the snapshot
        with self.rbac_utils.override_role(self):
            self.snapshots_client.show_snapshot(
                self.snapshot['id'])['snapshot']

    @decorators.idempotent_id('5d6f5f21-9293-4f2a-8f44-cabdc24d92cb')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:extended_snapshot_attributes"])
    def test_show_snapshot_with_extended_attributes(self):
        """List snapshots with extended attributes."""
        expected_attrs = ('os-extended-snapshot-attributes:project_id',
                          'os-extended-snapshot-attributes:progress')

        with self.rbac_utils.override_role(self):
            resp = self.snapshots_client.show_snapshot(
                self.snapshot['id'])['snapshot']
        for expected_attr in expected_attrs:
            if expected_attr not in resp:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=expected_attr)

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:update_snapshot"])
    @decorators.idempotent_id('53fe8ee3-3bea-4ae8-a979-3c98ea72f620')
    def test_update_snapshot(self):
        new_desc = 'This is the new description of snapshot.'
        params = {'description': new_desc}
        # Updates snapshot with new values
        with self.rbac_utils.override_role(self):
            self.snapshots_client.update_snapshot(
                self.snapshot['id'], **params)['snapshot']
        waiters.wait_for_volume_resource_status(
            self.snapshots_client, self.snapshot['id'], 'available')

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:delete_snapshot"])
    @decorators.idempotent_id('c7fe54ec-3b70-4772-ba11-f166d95888a3')
    def test_delete_snapshot(self):
        # Create a temp snapshot
        temp_snapshot = self.create_snapshot(self.volume['id'])
        with self.rbac_utils.override_role(self):
            # Delete the snapshot
            self.snapshots_client.delete_snapshot(temp_snapshot['id'])
        self.snapshots_client.wait_for_resource_deletion(
            temp_snapshot['id'])

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_all_snapshots"])
    @decorators.idempotent_id('e4edf0c0-2cd3-420f-b8ab-4d98a0718608')
    def test_list_snapshots(self):
        """List snapshots with params."""
        params = {'name': self.snapshot['name']}
        with self.rbac_utils.override_role(self):
            self._list_by_param_values(**params)

    @decorators.idempotent_id('f3155d8e-45ee-45c9-910d-18c0242229e1')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume:get_all_snapshots"])
    def test_list_snapshots_details(self):
        """List snapshots details with params."""
        params = {'name': self.snapshot['name']}
        with self.rbac_utils.override_role(self):
            self._list_by_param_values(with_detail=True, **params)

    @decorators.idempotent_id('dd37f388-2731-446d-a78f-676997ebb04a')
    @rbac_rule_validation.action(
        service="cinder",
        rules=["volume_extension:extended_snapshot_attributes"])
    def test_list_snapshots_details_with_extended_attributes(self):
        """List snapshots details with extended attributes."""
        expected_attrs = ('os-extended-snapshot-attributes:project_id',
                          'os-extended-snapshot-attributes:progress')
        params = {'name': self.snapshot['name']}

        with self.rbac_utils.override_role(self):
            resp = self._list_by_param_values(with_detail=True, **params)
        for expected_attr in expected_attrs:
            if expected_attr not in resp[0]:
                raise rbac_exceptions.RbacMissingAttributeResponseBody(
                    attribute=expected_attr)
