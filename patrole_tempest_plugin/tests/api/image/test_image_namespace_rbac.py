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


class ImageNamespacesRbacTest(rbac_base.BaseV2ImageRbacTest):

    @rbac_rule_validation.action(service="glance",
                                 rules=["add_metadef_namespace"])
    @decorators.idempotent_id('e0730ead-b824-4ffc-b774-9469df0e4da6')
    def test_create_metadef_namespace(self):
        """Create Image Metadef Namespace Test

        RBAC test for the glance add_metadef_namespace policy
        """
        namespace_name = data_utils.rand_name(
            self.__class__.__name__ + '-test-ns')
        with self.rbac_utils.override_role(self):
            self.namespaces_client.create_namespace(
                namespace=namespace_name,
                protected=False)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.namespaces_client.delete_namespace,
            namespace_name)

    @rbac_rule_validation.action(service="glance",
                                 rules=["get_metadef_namespaces"])
    @decorators.idempotent_id('f0b12538-9047-489e-98a5-2d78f48ce789')
    def test_list_metadef_namespaces(self):
        """List Image Metadef Namespace Test

        RBAC test for the glance get_metadef_namespaces policy
        """
        with self.rbac_utils.override_role(self):
            self.namespaces_client.list_namespaces()

    @rbac_rule_validation.action(service="glance",
                                 rules=["modify_metadef_namespace"])
    @decorators.idempotent_id('72c14a7e-927d-4f1a-9e1f-25475552922b')
    def test_modify_metadef_namespace(self):
        """Modify Image Metadef Namespace Test

        RBAC test for the glance modify_metadef_namespace policy
        """
        namespace_name = data_utils.rand_name(
            self.__class__.__name__ + '-test-ns')
        body = self.namespaces_client.create_namespace(
            namespace=namespace_name,
            protected=False)
        with self.rbac_utils.override_role(self):
            self.namespaces_client.update_namespace(
                body['namespace'], description="My new description")
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.namespaces_client.delete_namespace,
            namespace_name)
