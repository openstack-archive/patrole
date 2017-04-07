# Copyright 2017 AT&T Corporation.
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

from tempest.api.volume import base as vol_base
from tempest import config

from patrole_tempest_plugin.rbac_utils import rbac_utils

CONF = config.CONF


class BaseVolumeRbacTest(vol_base.BaseVolumeTest):

    credentials = ['admin', 'primary']

    @classmethod
    def skip_checks(cls):
        super(BaseVolumeRbacTest, cls).skip_checks()
        if not CONF.rbac.enable_rbac:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseVolumeRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.rbac_utils = rbac_utils()
        cls.rbac_utils.switch_role(cls, toggle_rbac_role=False)


class BaseVolumeAdminRbacTest(vol_base.BaseVolumeAdminTest):

    credentials = ['admin', 'primary']

    @classmethod
    def skip_checks(cls):
        super(BaseVolumeAdminRbacTest, cls).skip_checks()
        if not CONF.rbac.enable_rbac:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseVolumeAdminRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.rbac_utils = rbac_utils()
        cls.rbac_utils.switch_role(cls, toggle_rbac_role=False)
        version_checker = {
            1: [cls.os.volume_hosts_client, cls.os.volume_types_client],
            2: [cls.os.volume_hosts_v2_client, cls.os.volume_types_v2_client],
            3: [cls.os.volume_hosts_v2_client, cls.os.volume_types_v2_client]
        }
        cls.volume_hosts_client, cls.volume_types_client = \
            version_checker[cls._api_version]
