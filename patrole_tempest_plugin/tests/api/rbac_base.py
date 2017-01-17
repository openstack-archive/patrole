# Copyright 2017 at&t
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

# Maybe these should be in lib or recreated?
from tempest.api.image import base as image_base
from tempest.api.network import base as network_base
from tempest.api.volume import base as vol_base
from tempest import config

CONF = config.CONF


class BaseV2ImageRbacTest(image_base.BaseV2ImageTest):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BaseV2ImageRbacTest, cls).skip_checks()
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)
        if 'admin' not in CONF.auth.tempest_roles:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseV2ImageRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.admin_client = cls.os_adm.image_client_v2


class BaseVolumeRbacTest(vol_base.BaseVolumeTest):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BaseVolumeRbacTest, cls).skip_checks()
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)
        if 'admin' not in CONF.auth.tempest_roles:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseVolumeRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.admin_client = cls.os_adm.volumes_client


class BaseVolumeAdminRbacTest(vol_base.BaseVolumeAdminTest):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BaseVolumeAdminRbacTest, cls).skip_checks()
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)
        if 'admin' not in CONF.auth.tempest_roles:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseVolumeAdminRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.admin_client = cls.os_adm.volumes_client


class BaseNetworkRbacTest(network_base.BaseNetworkTest):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BaseNetworkRbacTest, cls).skip_checks()
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)
        if 'admin' not in CONF.auth.tempest_roles:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseNetworkRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.admin_client = cls.os_adm.agents_client
