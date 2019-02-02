# Copyright 2018 AT&T Corporation.
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity import rbac_base


CONF = config.CONF


class ApplicationCredentialsV3RbacTest(rbac_base.BaseIdentityV3RbacTest):

    @classmethod
    def skip_checks(cls):
        super(ApplicationCredentialsV3RbacTest, cls).skip_checks()
        if not CONF.identity_feature_enabled.application_credentials:
            raise cls.skipException("Application credentials are not available"
                                    " in this environment")

    @classmethod
    def resource_setup(cls):
        super(ApplicationCredentialsV3RbacTest, cls).resource_setup()
        cls.user_id = cls.os_primary.credentials.user_id

    def _create_application_credential(self, name=None, **kwargs):
        name = name or data_utils.rand_name('application_credential')
        application_credential = (
            self.application_credentials_client.create_application_credential(
                self.user_id, name=name, **kwargs))['application_credential']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.application_credentials_client.delete_application_credential,
            self.user_id,
            application_credential['id'])
        return application_credential

    @decorators.idempotent_id('b53bee14-e9df-4929-b257-6def76c12e4d')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:create_application_credential"])
    def test_create_application_credential(self):
        with self.override_role():
            self._create_application_credential()

    @decorators.idempotent_id('58b3c3a0-5ad0-44f7-8da7-0736f71f7168')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:list_application_credentials"])
    def test_list_application_credentials(self):
        with self.override_role():
            self.application_credentials_client.list_application_credentials(
                user_id=self.user_id)

    @decorators.idempotent_id('d7b13968-a8a6-47fd-8e1d-7cc7f565c7f8')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:get_application_credential"])
    def test_show_application_credential(self):
        app_cred = self._create_application_credential()
        with self.override_role():
            self.application_credentials_client.show_application_credential(
                user_id=self.user_id, application_credential_id=app_cred['id'])

    @decorators.idempotent_id('521b7c0f-1dd5-47a6-ae95-95c0323d7735')
    @rbac_rule_validation.action(
        service="keystone",
        rules=["identity:delete_application_credential"])
    def test_delete_application_credential(self):
        app_cred = self._create_application_credential()
        with self.override_role():
            self.application_credentials_client.delete_application_credential(
                user_id=self.user_id, application_credential_id=app_cred['id'])
