# Copyright 2018 AT&T Corporation.
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

import random

from tempest.common import utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class SegmentsExtRbacTest(base.BaseNetworkExtRbacTest):

    @classmethod
    def skip_checks(cls):
        super(SegmentsExtRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('segment', 'network'):
            msg = "segment extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(SegmentsExtRbacTest, cls).resource_setup()
        cls.network = cls.create_network()

    @classmethod
    def get_free_segmentation_id(cls):
        # Select unused segmentation_id to prevent usage conflict
        segments = cls.ntp_client.list_segments()["segments"]
        segmentation_ids = [s["segmentation_id"] for s in segments]

        # With 2+ concurrency, tests that ran in the same moment may fail due
        # to usage conflict. To prevent it we select segmentation to start
        # randomly.
        segmentation_id = random.randint(1000, 5000)
        while segmentation_id in segmentation_ids:
            segmentation_id += 1

        return segmentation_id

    @classmethod
    def create_segment(cls, network):
        segmentation_id = cls.get_free_segmentation_id()

        seg = cls.ntp_client.create_segment(
            network_id=network['id'], network_type="gre",
            segmentation_id=segmentation_id)
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.ntp_client.delete_segment, seg['segment']['id'])

        return seg

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08126')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_segment"])
    def test_create_segment(self):
        """Create segment.

        RBAC test for the neutron "create_segment" policy
        """
        with self.rbac_utils.override_role(self):
            self.create_segment(self.network)

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08127')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_segment"],
                                 expected_error_codes=[404])
    def test_show_segment(self):
        """Show segment.

        RBAC test for the neutron "get_segment" policy
        """
        segment = self.create_segment(self.network)

        with self.rbac_utils.override_role(self):
            self.ntp_client.show_segment(segment['segment']['id'])

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08128')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_segment",
                                        "update_segment"],
                                 expected_error_codes=[404, 403])
    def test_update_segment(self):
        """Update segment.

        RBAC test for the neutron "update_segment" policy
        """
        segment = self.create_segment(self.network)

        with self.rbac_utils.override_role(self):
            self.ntp_client.update_segment(segment['segment']['id'],
                                           name="NewName")

    @decorators.idempotent_id('c02618e7-bb20-1a3a-83c8-6eec2af08129')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_segment",
                                        "delete_segment"],
                                 expected_error_codes=[404, 403])
    def test_delete_segment(self):
        """Delete segment.

        RBAC test for the neutron "delete_segment" policy
        """
        segment = self.create_segment(self.network)

        with self.rbac_utils.override_role(self):
            self.ntp_client.delete_segment(segment['segment']['id'])

    @decorators.idempotent_id('d68a0578-36ae-435e-8aaa-508ee96bdfae')
    @rbac_rule_validation.action(service="neutron", rules=["get_segment"])
    def test_list_segments(self):
        """List segments.

        RBAC test for the neutron ``list_segments`` function and
        the``get_segment`` policy
        """
        admin_resource_id = self.create_segment(self.network)['segment']['id']
        with (self.rbac_utils.override_role_and_validate_list(
                self, admin_resource_id=admin_resource_id)) as ctx:
            ctx.resources = self.ntp_client.list_segments(
                id=admin_resource_id)["segments"]
