#    Copyright 2017 AT&T Corporation.
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

from tempest.api.image import base as image_base

from patrole_tempest_plugin import rbac_utils


class BaseV2ImageRbacTest(rbac_utils.RbacUtilsMixin,
                          image_base.BaseV2ImageTest):

    @classmethod
    def setup_clients(cls):
        super(BaseV2ImageRbacTest, cls).setup_clients()
        cls.namespaces_client = cls.os_primary.namespaces_client
        cls.resource_types_client = cls.os_primary.resource_types_client
        cls.namespace_properties_client =\
            cls.os_primary.namespace_properties_client
        cls.namespace_objects_client = cls.os_primary.namespace_objects_client
        cls.namespace_tags_client = cls.os_primary.namespace_tags_client
