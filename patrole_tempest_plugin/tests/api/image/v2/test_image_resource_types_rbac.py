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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base


class ImageResourceTypesRbacTest(rbac_base.BaseV2ImageRbacTest):

    @classmethod
    def resource_setup(cls):
        super(ImageResourceTypesRbacTest, cls).resource_setup()
        cls.namespace_name = data_utils.rand_name('test-ns')
        cls.namespaces_client.create_namespace(
            namespace=cls.namespace_name,
            protected=False)

    @classmethod
    def resource_cleanup(cls):
        test_utils.call_and_ignore_notfound_exc(
            cls.namespaces_client.delete_namespace,
            cls.namespace_name)
        super(ImageResourceTypesRbacTest, cls).resource_setup()

    @rbac_rule_validation.action(service="glance",
                                 rule="list_metadef_resource_types")
    @decorators.idempotent_id('0416fc4d-cfdc-447b-88b6-d9f1dd0382f7')
    def test_list_metadef_resource_types(self):
        """List Metadef Resource Type Image Test

        RBAC test for the glance list_metadef_resource_type policy.
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.resource_types_client.list_resource_types()

    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_resource_type")
    @decorators.idempotent_id('3698d53c-71ae-4803-a2c3-c272c054f25c')
    def test_get_metadef_resource_type(self):
        """Get Metadef Resource Type Image Test

        RBAC test for the glance get_metadef_resource_type policy.
        """
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.resource_types_client.list_resource_type_association(
            self.namespace_name)

    @rbac_rule_validation.action(service="glance",
                                 rule="add_metadef_resource_type_association")
    @decorators.idempotent_id('ef9fbc60-3e28-4164-a25c-d30d892f7939')
    def test_add_metadef_resource_type(self):
        type_name = data_utils.rand_name()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.resource_types_client.create_resource_type_association(
            self.namespace_name, name=type_name)
