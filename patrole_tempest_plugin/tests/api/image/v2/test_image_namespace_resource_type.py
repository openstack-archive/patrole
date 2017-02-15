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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.rbac_utils import rbac_utils
from patrole_tempest_plugin.tests.api.image import rbac_base

CONF = config.CONF


class ImageNamespacesResourceTypeRbacTest(rbac_base.BaseV2ImageRbacTest):

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(ImageNamespacesResourceTypeRbacTest, self).tearDown()

    @rbac_rule_validation.action(service="glance",
                                 rule="list_metadef_resource_types")
    @decorators.idempotent_id('0416fc4d-cfdc-447b-88b6-d9f1dd0382f7')
    def test_list_metadef_resource_types(self):
        """List Metadef Resource Type Image Test

        RBAC test for the glance list_metadef_resource_type policy.
        """
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.resource_types_client.list_resource_types()

    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_resource_type")
    @decorators.idempotent_id('3698d53c-71ae-4803-a2c3-c272c054f25c')
    def test_get_metadef_resource_type(self):
        """Get Metadef Resource Type Image Test

        RBAC test for the glance get_metadef_resource_type policy.
        """
        namespace_name = data_utils.rand_name('test-ns')
        self.namespaces_client.create_namespace(
            namespace=namespace_name,
            protected=False)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.namespaces_client.delete_namespace,
            namespace_name)

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.resource_types_client.list_resource_type_association(
            namespace_name)
