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

from tempest.api.identity import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from patrole_tempest_plugin.rbac_utils import rbac_utils

CONF = config.CONF


class BaseIdentityV2AdminRbacTest(base.BaseIdentityV2AdminTest):

    credentials = ['admin', 'primary']

    @classmethod
    def skip_checks(cls):
        super(BaseIdentityV2AdminRbacTest, cls).skip_checks()
        if not CONF.rbac.enable_rbac:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseIdentityV2AdminRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.tenants_client = cls.os.tenants_client
        cls.users_client = cls.os.users_client
        cls.rbac_utils = rbac_utils()
        cls.rbac_utils.switch_role(cls, toggle_rbac_role=False)

    def _create_service(self):
        name = data_utils.rand_name('service')
        type = data_utils.rand_name('type')

        self.service = self.services_client.create_service(
            name=name, type=type,
            description="description")
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.services_client.delete_service,
                        self.service['OS-KSADM:service']['id'])
        return self.service

    def _create_user(self, name=None, email=None, password=None, **kwargs):
        """Set up a test user."""
        if name is None:
            name = data_utils.rand_name('test_user')
        if email is None:
            email = name + '@testmail.tm'
        if password is None:
            password = data_utils.rand_password()
        user = self.users_client.create_user(
            name=name, email=email, password=password, **kwargs)['user']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.users_client.delete_user,
                        user['id'])
        return user

    def _create_tenant(self):
        """Set up a test tenant."""
        name = data_utils.rand_name('test_tenant')
        tenant = self.projects_client.create_tenant(
            name=name,
            description=data_utils.rand_name('desc'))['tenant']
        # Delete the tenant at the end of the test
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.tenants_client.delete_tenant,
                        tenant['id'])
        return tenant
