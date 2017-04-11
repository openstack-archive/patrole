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
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base


class NamespacesPropertyRbacTest(rbac_base.BaseV2ImageRbacTest):

    @classmethod
    def resource_setup(cls):
        super(NamespacesPropertyRbacTest, cls).resource_setup()
        body = cls.resource_types_client.list_resource_types()
        cls.resource_name = body['resource_types'][0]['name']

    @rbac_rule_validation.action(service="glance",
                                 rule="add_metadef_property")
    @decorators.idempotent_id('383555ca-677b-43e9-b809-acc2b5a0176c')
    def test_add_md_properties(self):
        """Create Image Metadef Namespace Property Test

        RBAC test for the glance add_metadef_property policy
        """
        namespace = self.create_namespace()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        property_name = data_utils.rand_name('test-ns-property')
        self.namespace_properties_client.create_namespace_property(
            namespace=namespace['namespace'], type="string",
            title=property_name, name=self.resource_name)

    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_properties")
    @decorators.idempotent_id('d5177611-c2b5-4000-bd9c-1987af9222ea')
    def test_get_md_properties(self):
        """List Image Metadef Namespace Properties Test

        RBAC test for the glance get_metadef_properties policy
        """
        namespace = self.create_namespace()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.namespace_properties_client.list_namespace_properties(
            namespace=namespace['namespace'])

    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_property")
    @decorators.idempotent_id('cfeda2af-bcab-433e-80c7-4b40c774aed5')
    def test_get_md_property(self):
        """Get Image Metadef Namespace Property Test

        RBAC test for the glance get_metadef_property policy
        """
        namespace = self.create_namespace()
        property_name = data_utils.rand_name('test-ns-property')
        self.namespace_properties_client.create_namespace_property(
            namespace=namespace['namespace'], type="string",
            title=property_name, name=self.resource_name)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.namespace_properties_client.show_namespace_properties(
            namespace['namespace'], self.resource_name)

    @rbac_rule_validation.action(service="glance",
                                 rule="modify_metadef_property")
    @decorators.idempotent_id('fdaf9363-4010-4f2f-8192-1b28f6b22e69')
    def test_modify_md_properties(self):
        """Modify Image Metadef Namespace Policy Test

        RBAC test for the glance modify_metadef_property policy
        """
        namespace = self.create_namespace()
        property_name = data_utils.rand_name('test-ns-property')
        self.namespace_properties_client.create_namespace_property(
            namespace=namespace['namespace'], type="string",
            title=property_name, name=self.resource_name)

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.namespace_properties_client.update_namespace_properties(
            namespace['namespace'], self.resource_name, type="string",
            title=property_name, name=self.resource_name)
