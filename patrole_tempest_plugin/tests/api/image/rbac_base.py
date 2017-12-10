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
from tempest import config

from patrole_tempest_plugin import rbac_utils

CONF = config.CONF


class BaseV2ImageRbacTest(rbac_utils.RbacUtilsMixin,
                          image_base.BaseV2ImageTest):

    @classmethod
    def skip_checks(cls):
        super(BaseV2ImageRbacTest, cls).skip_checks()
        cls.skip_rbac_checks()

    @classmethod
    def setup_clients(cls):
        super(BaseV2ImageRbacTest, cls).setup_clients()
        cls.setup_rbac_utils()
