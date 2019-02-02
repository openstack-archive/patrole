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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base


class MeteringLabelsRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(MeteringLabelsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('metering', 'network'):
            msg = "metering extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(MeteringLabelsRbacTest, cls).setup_clients()
        cls.metering_labels_client = cls.os_primary.metering_labels_client

    def _create_metering_label(self):
        body = self.metering_labels_client.create_metering_label(
            name=data_utils.rand_name(self.__class__.__name__))

        label = body['metering_label']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.metering_labels_client.delete_metering_label,
                        label['id'])
        return label

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_metering_label"])
    @decorators.idempotent_id('e8cfc8b8-c159-48f0-93b3-591625a02f8b')
    def test_create_metering_label(self):
        """Create metering label.

        RBAC test for the neutron "create_metering_label" policy
        """
        with self.override_role():
            self._create_metering_label()

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_metering_label"],
                                 expected_error_codes=[404])
    @decorators.idempotent_id('c57f6636-c702-4755-8eac-5e73bc1f7d14')
    def test_show_metering_label(self):
        """Show metering label.

        RBAC test for the neutron "get_metering_label" policy
        """
        label = self._create_metering_label()
        with self.override_role():
            self.metering_labels_client.show_metering_label(label['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_metering_label",
                                        "delete_metering_label"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('1621ccfe-2e3f-4d16-98aa-b620f9d00404')
    def test_delete_metering_label(self):
        """Delete metering label.

        RBAC test for the neutron "delete_metering_label" policy
        """
        label = self._create_metering_label()
        with self.override_role():
            self.metering_labels_client.delete_metering_label(label['id'])

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_metering_label"])
    @decorators.idempotent_id('d60d72b0-cb8f-44db-b10b-5092fa01cb0e')
    def test_list_metering_labels(self):
        """List metering label.

        RBAC test for the neutron ``list_metering_labels`` function and
        the ``get_metering_label`` policy
        """
        admin_resource_id = self._create_metering_label()['id']
        with (self.override_role_and_validate_list(
                admin_resource_id=admin_resource_id)) as ctx:
            ctx.resources = (
                self.metering_labels_client.
                list_metering_labels(id=admin_resource_id)
                ["metering_labels"])
