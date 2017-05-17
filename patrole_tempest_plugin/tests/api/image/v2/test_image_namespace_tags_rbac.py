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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.image import rbac_base as base


class NamespaceTagsRbacTest(base.BaseV2ImageRbacTest):
    """RBAC tests for namespace_tags_client.

    Performs RBAC testing for the endpoints in namespace_tags_client, except
    for

        1) delete_namespace_tag
        2) delete_namespace_tags

    because Glance does not currently do policy enforcement for them.
    """

    @classmethod
    def resource_setup(cls):
        super(NamespaceTagsRbacTest, cls).resource_setup()
        cls.namespace = cls.namespaces_client.create_namespace(
            namespace=data_utils.rand_name(
                cls.__name__ + '-namespace'))['namespace']

    @classmethod
    def resource_cleanup(cls):
        cls.namespaces_client.delete_namespace(cls.namespace)
        super(NamespaceTagsRbacTest, cls).resource_cleanup()

    def _create_namespace_tag(self, multiple=False):
        tag_count = 2 if multiple else 1
        namespace_tag_names = []

        for i in range(tag_count):
            tag_name = data_utils.rand_name(self.__class__.__name__ + '-tag')
            namespace_tag_names.append({'name': tag_name})

        if multiple:
            namespace_tags = self.namespace_tags_client.create_namespace_tags(
                self.namespace, tags=namespace_tag_names)['tags']
        else:
            namespace_tags = self.namespace_tags_client.create_namespace_tag(
                self.namespace, namespace_tag_names[0]['name'])

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.namespace_tags_client.delete_namespace_tags,
                        self.namespace)

        return [nt['name'] for nt in namespace_tags] if multiple \
            else namespace_tags['name']

    @decorators.idempotent_id('50bedccb-9d0b-4138-8d95-31a89250edf6')
    @rbac_rule_validation.action(service="glance",
                                 rule="add_metadef_tag")
    def test_create_namespace_tag(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_namespace_tag()

    @decorators.idempotent_id('4acf70cc-05da-4b1e-87b2-d5e4475164e7')
    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_tag")
    def test_show_namespace_tag(self):
        tag_name = self._create_namespace_tag()
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.namespace_tags_client.show_namespace_tag(self.namespace, tag_name)

    @decorators.idempotent_id('01593828-3edb-461e-8abc-8fdeb3927e37')
    @rbac_rule_validation.action(service="glance",
                                 rule="modify_metadef_tag")
    def test_update_namespace_tag(self):
        tag_name = self._create_namespace_tag()
        updated_tag_name = data_utils.rand_name(
            self.__class__.__name__ + '-tag')

        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.namespace_tags_client.update_namespace_tag(
            self.namespace, tag_name, name=updated_tag_name)

    @decorators.idempotent_id('20ffaf76-ebdc-4267-a1ad-194346f5cc91')
    @rbac_rule_validation.action(service="glance",
                                 rule="add_metadef_tags")
    def test_create_namespace_tags(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self._create_namespace_tag(multiple=True)

    @decorators.idempotent_id('d37c1501-e787-449d-89b3-754a942a459a')
    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_tags")
    def test_list_namespace_tags(self):
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        self.namespace_tags_client.list_namespace_tags(self.namespace)
