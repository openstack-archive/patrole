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
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

from tempest import config

CONF = config.CONF


class VolumeRbacTest(rbac_base.BaseV2ComputeRbacTest):
    """RBAC tests for the Nova Volume client."""

    # These tests will fail with a 404 starting from microversion 2.36.
    # For more information, see:
    # https://developer.openstack.org/api-ref/compute/#volume-extension-os-volumes-os-snapshots-deprecated
    max_microversion = '2.35'

    @classmethod
    def resource_setup(cls):
        super(VolumeRbacTest, cls).resource_setup()
        cls.volume = cls.create_volume()

    def _delete_snapshot(self, snapshot_id):
        waiters.wait_for_volume_resource_status(
            self.os_admin.snapshots_extensions_client, snapshot_id,
            'available')
        self.snapshots_extensions_client.delete_snapshot(snapshot_id)
        self.os_admin.snapshots_extensions_client.wait_for_resource_deletion(
            snapshot_id)

    @decorators.idempotent_id('2402013e-a624-43e3-9518-44a5d1dbb32d')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_create_volume(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        volume = self.volumes_extensions_client.create_volume(
            size=CONF.volume.volume_size)['volume']
        # Use the admin volumes client to wait, because waiting involves
        # calling show API action which enforces a different policy.
        waiters.wait_for_volume_resource_status(self.os_admin.volumes_client,
                                                volume['id'], 'available')
        # Use non-deprecated volumes_client for deletion.
        self.addCleanup(self.volumes_client.delete_volume, volume['id'])

    @decorators.idempotent_id('69b3888c-dff2-47b0-9fa4-0672619c9054')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_list_volumes(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_extensions_client.list_volumes()

    @decorators.idempotent_id('4ba0a820-040f-488b-86bb-be2e920ea12c')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_show_volume(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_extensions_client.show_volume(self.volume['id'])

    @decorators.idempotent_id('6e7870f2-1bb2-4b58-96f8-6782071ef327')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_delete_volume(self):
        volume = self.create_volume()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.volumes_extensions_client.delete_volume(volume['id'])

    @decorators.idempotent_id('0c3eaa4f-69d6-4a13-9dda-19585f36b1c1')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_create_snapshot(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        snapshot = self.snapshots_extensions_client.create_snapshot(
            self.volume['id'])['snapshot']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_snapshot, snapshot['id'])

    @decorators.idempotent_id('e944e816-416c-11e7-a919-92ebcb67fe33')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_list_snapshots(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.snapshots_extensions_client.list_snapshots()

    @decorators.idempotent_id('19c2e6bd-585b-472f-a8d7-71ea9299c655')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_show_snapshot(self):
        snapshot = self.snapshots_extensions_client.create_snapshot(
            self.volume['id'])['snapshot']
        self.addCleanup(self._delete_snapshot, snapshot['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.snapshots_extensions_client.show_snapshot(snapshot['id'])

    @decorators.idempotent_id('f4f5635c-416c-11e7-a919-92ebcb67fe33')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-volumes")
    def test_delete_snapshot(self):
        snapshot = self.snapshots_extensions_client.create_snapshot(
            self.volume['id'])['snapshot']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_snapshot, snapshot['id'])

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._delete_snapshot(snapshot['id'])
