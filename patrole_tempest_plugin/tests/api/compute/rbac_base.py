# Copyright 2017 AT&T Corporation
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

from tempest.api.compute import base as compute_base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from patrole_tempest_plugin import rbac_utils

CONF = config.CONF


class BaseV2ComputeRbacTest(compute_base.BaseV2ComputeTest):

    credentials = ['admin', 'primary']

    @classmethod
    def skip_checks(cls):
        super(BaseV2ComputeRbacTest, cls).skip_checks()
        if not CONF.rbac.enable_rbac:
            raise cls.skipException(
                '%s skipped as RBAC flag not enabled' % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseV2ComputeRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os_primary.auth_provider
        cls.rbac_utils = rbac_utils.RbacUtils(cls)

        cls.hosts_client = cls.os_primary.hosts_client
        cls.tenant_usages_client = cls.os_primary.tenant_usages_client

    @classmethod
    def resource_setup(cls):
        super(BaseV2ComputeRbacTest, cls).resource_setup()
        cls.flavors = []

    @classmethod
    def resource_cleanup(cls):
        cls.clear_flavors()
        super(BaseV2ComputeRbacTest, cls).resource_cleanup()

    @classmethod
    def clear_flavors(cls):
        for flavor in cls.flavors:
            test_utils.call_and_ignore_notfound_exc(
                cls.flavors_client.delete_flavor, flavor['id'])

    @classmethod
    def _create_flavor(cls, **kwargs):
        flavor_kwargs = {
            "name": data_utils.rand_name(cls.__name__ + '-flavor'),
            "ram": data_utils.rand_int_id(1, 10),
            "vcpus": data_utils.rand_int_id(1, 10),
            "disk": data_utils.rand_int_id(1, 10),
            "id": data_utils.rand_uuid(),
        }
        if kwargs:
            flavor_kwargs.update(kwargs)
        flavor = cls.flavors_client.create_flavor(**flavor_kwargs)['flavor']
        cls.flavors.append(flavor)
        return flavor
