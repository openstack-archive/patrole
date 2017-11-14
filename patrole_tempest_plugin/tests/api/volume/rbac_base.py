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
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from patrole_tempest_plugin import rbac_utils

CONF = config.CONF


class BaseVolumeRbacTest(vol_base.BaseVolumeTest):
    # NOTE(felipemonteiro): Patrole currently only tests the v3 Cinder API
    # because it is the current API and because policy enforcement does not
    # change between API major versions. So, it is not necessary to specify
    # the `_api_version` in any test class. However, specify microversions in
    # subclasses if necessary.
    _api_version = 3

    @classmethod
    def skip_checks(cls):
        super(BaseVolumeRbacTest, cls).skip_checks()
        if not CONF.patrole.enable_rbac:
            raise cls.skipException(
                "%s skipped as RBAC testing not enabled" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseVolumeRbacTest, cls).setup_clients()
        cls.rbac_utils = rbac_utils.RbacUtils(cls)

        cls.volume_hosts_client = cls.os_primary.volume_hosts_v2_client
        cls.volume_types_client = cls.os_primary.volume_types_v2_client
        cls.groups_client = cls.os_primary.groups_v3_client
        cls.group_types_client = cls.os_primary.group_types_v3_client

    @classmethod
    def create_volume_type(cls, name=None, **kwargs):
        """Create a test volume-type"""
        name = name or data_utils.rand_name(cls.__name__ + '-volume-type')
        volume_type = cls.volume_types_client.create_volume_type(
            name=name, **kwargs)['volume_type']
        cls.addClassResourceCleanup(
            cls.volume_types_client.wait_for_resource_deletion,
            volume_type['id'])
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.volume_types_client.delete_volume_type, volume_type['id'])
        return volume_type

    def create_group_type(self, name=None, ignore_notfound=False, **kwargs):
        """Create a test group-type"""
        name = name or data_utils.rand_name(
            self.__class__.__name__ + '-group-type')
        group_type = self.group_types_client.create_group_type(
            name=name, **kwargs)['group_type']

        if ignore_notfound:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.group_types_client.delete_group_type,
                            group_type['id'])
        else:
            self.addCleanup(self.group_types_client.delete_group_type,
                            group_type['id'])

        return group_type
