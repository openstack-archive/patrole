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

CONF = config.CONF


class BaseIdentityV3RbacAdminTest(base.BaseIdentityV3AdminTest):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BaseIdentityV3RbacAdminTest, cls).skip_checks()
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)
        if CONF.auth.tempest_roles != ['admin']:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseIdentityV3RbacAdminTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider
        cls.admin_client = cls.os_adm.identity_v3_client
        cls.creds_client = cls.os.credentials_client
        cls.services_client = cls.os.identity_services_v3_client

    def _create_service(self):
        """Creates a service for test."""
        name = data_utils.rand_name('service')
        serv_type = data_utils.rand_name('type')
        desc = data_utils.rand_name('description')
        service = self.services_client \
                      .create_service(name=name,
                                      type=serv_type,
                                      description=desc)['service']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.services_client.delete_service, service['id'])
        return service
