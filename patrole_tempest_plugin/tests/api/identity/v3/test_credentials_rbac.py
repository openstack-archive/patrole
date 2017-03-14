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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.identity.v3 import rbac_base


class IdentityCredentialsV3AdminRbacTest(
        rbac_base.BaseIdentityV3RbacAdminTest):

    def _create_credential(self):
        """Creates a user, project, and credential for test."""
        user = self.setup_test_user()
        user_id = user['id']
        project_id = user['project_id']
        keys = [data_utils.rand_name('Access'),
                data_utils.rand_name('Secret')]
        blob = "{\"access\": \"%s\", \"secret\": \"%s\"}" % (
            keys[0], keys[1])
        credential = self.creds_client \
                         .create_credential(user_id=user_id,
                                            project_id=project_id,
                                            blob=blob,
                                            type='ec2')['credential']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.creds_client.delete_credential, credential['id'])

        return (project_id, credential)

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:create_credential")
    @decorators.idempotent_id('c1ab6d34-c59f-4ae1-bae9-bb3c1089b48e')
    def test_create_credential(self):
        """Create a Credential.

        RBAC test for Keystone: identity:create_credential
        """
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_credential()

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:update_credential")
    @decorators.idempotent_id('cfb05ce3-bffb-496e-a3c2-9515d730da63')
    def test_update_credential(self):
        """Update a Credential.

        RBAC test for Keystone: identity:update_credential
        """
        project_id, credential = self._create_credential()
        # Update blob keys
        new_keys = [data_utils.rand_name('NewAccess'),
                    data_utils.rand_name('NewSecret')]

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.creds_client \
            .update_credential(credential['id'],
                               credential=credential,
                               access_key=new_keys[0],
                               secret_key=new_keys[1],
                               project_id=project_id)['credential']

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:delete_credential")
    @decorators.idempotent_id('87ab42af-8d41-401b-90df-21e72919fcde')
    def test_delete_credential(self):
        """Delete a Credential.

        RBAC test for Keystone: identity:delete_credential
        """
        _, credential = self._create_credential()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.creds_client.delete_credential(credential['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:get_credential")
    @decorators.idempotent_id('1b6eeae6-f1e8-4cdf-8903-1c002b1fc271')
    def test_show_credential(self):
        """Show/Get a Credential.

        RBAC test for Keystone: identity:get_credential
        """
        _, credential = self._create_credential()

        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.creds_client.show_credential(credential['id'])

    @rbac_rule_validation.action(service="keystone",
                                 rule="identity:list_credentials")
    @decorators.idempotent_id('3de303e2-12a7-4811-805a-f18906472038')
    def test_list_credentials(self):
        """List all Credentials.

        RBAC test for Keystone: identity:list_credentials
        """
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.creds_client.list_credentials()
