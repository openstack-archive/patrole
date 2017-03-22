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


class BaseIdentityV3RbacAdminTest(base.BaseIdentityV3AdminTest):

    credentials = ['admin', 'primary']

    @classmethod
    def skip_checks(cls):
        super(BaseIdentityV3RbacAdminTest, cls).skip_checks()
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                "%s skipped as RBAC Flag not enabled" % cls.__name__)

    @classmethod
    def setup_clients(cls):
        super(BaseIdentityV3RbacAdminTest, cls).setup_clients()
        cls.auth_provider = cls.os.auth_provider

        cls.rbac_utils = rbac_utils()
        cls.rbac_utils.switch_role(cls, switchToRbacRole=False)

        cls.creds_client = cls.os.credentials_client
        cls.domains_client = cls.os.domains_client
        cls.endpoints_client = cls.os.endpoints_v3_client
        cls.groups_client = cls.os.groups_client
        cls.projects_client = cls.os.projects_client
        cls.policies_client = cls.os.policies_client
        cls.regions_client = cls.os.regions_client
        cls.roles_client = cls.os.roles_v3_client
        cls.services_client = cls.os.identity_services_v3_client
        cls.users_client = cls.os.users_v3_client

    def setup_test_credential(self, user=None):
        """Creates a user, project, and credential for test."""
        keys = [data_utils.rand_uuid_hex(),
                data_utils.rand_uuid_hex()]
        blob = '{"access": "%s", "secret": "%s"}' % (keys[0], keys[1])
        credential = self.creds_client.create_credential(
            user_id=user['id'],
            project_id=user['project_id'],
            blob=blob,
            type='ec2')['credential']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.creds_client.delete_credential,
                        credential['id'])

        return credential

    def setup_test_domain(self):
        """Set up a test domain."""
        domain = self.domains_client.create_domain(
            name=data_utils.rand_name('test_domain'),
            description=data_utils.rand_name('desc'))['domain']
        # Delete the domain at the end of the test, but the domain must be
        # disabled first (cleanup called in reverse order)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.domains_client.delete_domain,
                        domain['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.domains_client.update_domain,
                        domain['id'],
                        enabled=False)
        return domain

    def setup_test_endpoint(self, service=None):
        """Creates a service and an endpoint for test."""
        interface = 'public'
        url = data_utils.rand_url()
        # Endpoint creation requires a service
        if service is None:
            service = self.setup_test_service()
        endpoint = self.endpoints_client.create_endpoint(
            service_id=service['id'],
            interface=interface,
            url=url)['endpoint']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.endpoints_client.delete_endpoint,
                        endpoint['id'])
        return endpoint

    def setup_test_group(self):
        """Creates a group for test."""
        name = data_utils.rand_name('test_group')
        group = self.groups_client.create_group(name=name)['group']
        # Delete the group at the end of the test
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.groups_client.delete_group,
                        group['id'])
        return group

    def setup_test_policy(self):
        """Creates a policy for test."""
        blob = data_utils.rand_name('test_blob')
        policy_type = data_utils.rand_name('PolicyType')
        policy = self.policies_client.create_policy(
            blob=blob,
            policy=policy_type,
            type="application/json")['policy']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.policies_client.delete_policy,
                        policy['id'])
        return policy

    def setup_test_project(self):
        """Set up a test project."""
        project = self.projects_client.create_project(
            name=data_utils.rand_name('test_project'),
            description=data_utils.rand_name('desc'))['project']
        # Delete the project at the end of the test
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.projects_client.delete_project,
                        project['id'])
        return project

    def setup_test_region(self):
        """Creates a region for test."""
        description = data_utils.rand_name('test_region_desc')

        region = self.regions_client.create_region(
            description=description)['region']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.regions_client.delete_region,
                        region['id'])
        return region

    def setup_test_role(self):
        """Set up a test role."""
        name = data_utils.rand_name('test_role')
        role = self.roles_client.create_role(name=name)['role']
        # Delete the role at the end of the test
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.roles_client.delete_role,
                        role['id'])
        return role

    def setup_test_service(self):
        """Setup a test service."""
        name = data_utils.rand_name('service')
        serv_type = data_utils.rand_name('type')
        desc = data_utils.rand_name('description')
        service = self.services_client.create_service(
            name=name,
            type=serv_type,
            description=desc)['service']
        # Delete the service at the end of the test
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.services_client.delete_service,
                        service['id'])
        return service

    def setup_test_user(self, password=None, **kwargs):
        """Set up a test user."""
        username = data_utils.rand_name('test_user')
        email = username + '@testmail.tm'
        user = self.users_client.create_user(
            name=username,
            email=email,
            password=password,
            **kwargs)['user']
        # Delete the user at the end of the test
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.users_client.delete_user,
                        user['id'])
        return user
