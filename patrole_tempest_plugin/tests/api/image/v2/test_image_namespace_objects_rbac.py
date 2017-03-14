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
from patrole_tempest_plugin.tests.api.image import rbac_base

CONF = config.CONF


class ImageNamespacesObjectsRbacTest(rbac_base.BaseV2ImageRbacTest):

    @rbac_rule_validation.action(service="glance",
                                 rule="add_metadef_object")
    @decorators.idempotent_id("772156f2-e33d-432e-8521-12385746c2f0")
    def test_create_metadef_object_in_namespace(self):
        """Create Metadef Object Namespace Test

        RBAC test for the glance add_metadef_object policy
        """
        namespace = self.create_namespace()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # create a md object, it will be cleaned automatically after
        # cleanup of namespace
        object_name = data_utils.rand_name('test-object')
        self.namespace_objects_client.create_namespace_object(
            namespace['namespace'],
            name=object_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.namespace_objects_client.delete_namespace_object,
                        namespace['namespace'], object_name)

    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_objects")
    @decorators.idempotent_id("48b50ecb-237d-4909-be62-b6a05c47b64d")
    def test_list_metadef_objects_in_namespace(self):
        """List Metadef Object Namespace Test

        RBAC test for the glance get_metadef_objects policy
        """
        namespace = self.create_namespace()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        # list md objects
        self.namespace_objects_client.list_namespace_objects(
            namespace['namespace'])

    @rbac_rule_validation.action(service="glance",
                                 rule="modify_metadef_object")
    @decorators.idempotent_id("cd130b1d-89fa-479c-a90e-498d895fb455")
    def test_update_metadef_object_in_namespace(self):
        """Update Metadef Object Namespace Test

        RBAC test for the glance modify_metadef_object policy
        """
        namespace = self.create_namespace()
        object_name = data_utils.rand_name('test-object')
        self.namespace_objects_client.create_namespace_object(
            namespace['namespace'],
            name=object_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.namespace_objects_client.delete_namespace_object,
                        namespace['namespace'], object_name)

        # Toggle role and modify object
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        new_name = "Object New Name"
        self.namespace_objects_client.update_namespace_object(
            namespace['namespace'], object_name, name=new_name)

    @rbac_rule_validation.action(service="glance",
                                 rule="get_metadef_object")
    @decorators.idempotent_id("93c61420-5b80-4a0e-b6f3-4ccc6e90b865")
    def test_show_metadef_object_in_namespace(self):
        """Show Metadef Object Namespace Test

        RBAC test for the glance get_metadef_object policy
        """
        namespace = self.create_namespace()
        object_name = data_utils.rand_name('test-object')
        self.namespace_objects_client.create_namespace_object(
            namespace['namespace'],
            name=object_name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.namespace_objects_client.delete_namespace_object,
                        namespace['namespace'], object_name)
        # Toggle role and get object
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.namespace_objects_client.show_namespace_object(
            namespace['namespace'],
            object_name)
