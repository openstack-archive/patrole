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

from oslo_log import log as logging

from tempest.api.identity import base
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from patrole_tempest_plugin import rbac_utils

LOG = logging.getLogger(__name__)


class BaseIdentityRbacTest(rbac_utils.RbacUtilsMixin,
                           base.BaseIdentityTest):

    @classmethod
    def setup_test_role(cls):
        """Set up a test role."""
        name = data_utils.rand_name(cls.__name__ + '-test_role')
        role = cls.roles_client.create_role(name=name)['role']
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.roles_client.delete_role, role['id'])

        return role

    @classmethod
    def setup_test_service(cls):
        """Setup a test service."""
        name = data_utils.rand_name(cls.__name__ + '-service')
        serv_type = data_utils.rand_name('type')
        desc = data_utils.rand_name(cls.__name__ + '-description')

        service = cls.services_client.create_service(
            name=name,
            type=serv_type,
            description=desc)['service']

        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.services_client.delete_service, service['id'])

        return service

    @classmethod
    def setup_test_user(cls, password=None, **kwargs):
        """Set up a test user."""
        username = data_utils.rand_name(cls.__name__ + '-test_user')
        email = username + '@testmail.tm'

        user = cls.users_client.create_user(
            name=username,
            email=email,
            password=password,
            **kwargs)['user']
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.users_client.delete_user, user['id'])

        return user


class BaseIdentityV3RbacTest(BaseIdentityRbacTest):

    identity_version = 'v3'
    credentials = ['primary']

    @classmethod
    def setup_clients(cls):
        super(BaseIdentityV3RbacTest, cls).setup_clients()
        cls.application_credentials_client = \
            cls.os_primary.application_credentials_client
        cls.creds_client = cls.os_primary.credentials_client
        cls.consumers_client = cls.os_primary.oauth_consumers_client
        cls.domains_client = cls.os_primary.domains_client
        cls.domain_config_client = cls.os_primary.domain_config_client
        cls.endpoints_client = cls.os_primary.endpoints_v3_client
        cls.endpoint_filter_client = cls.os_primary.endpoint_filter_client
        cls.endpoint_groups_client = cls.os_primary.endpoint_groups_client
        cls.groups_client = cls.os_primary.groups_client
        cls.identity_client = cls.os_primary.identity_v3_client
        cls.oauth_token_client = cls.os_primary.oauth_token_client
        cls.projects_client = cls.os_primary.projects_client
        cls.project_tags_client = cls.os_primary.project_tags_client
        cls.policies_client = cls.os_primary.policies_client
        cls.regions_client = cls.os_primary.regions_client
        cls.role_assignments_client = cls.os_primary.role_assignments_client
        cls.roles_client = cls.os_primary.roles_v3_client
        cls.services_client = cls.os_primary.identity_services_v3_client
        cls.token_client = cls.os_primary.token_v3_client
        cls.trusts_client = cls.os_primary.trusts_client
        cls.users_client = cls.os_primary.users_v3_client

    @classmethod
    def resource_setup(cls):
        super(BaseIdentityV3RbacTest, cls).resource_setup()
        cls.credentials = []
        cls.domains = []
        cls.groups = []
        cls.policies = []
        cls.projects = []
        cls.regions = []
        cls.trusts = []
        cls.tokens = []

    @classmethod
    def resource_cleanup(cls):
        for credential in cls.credentials:
            test_utils.call_and_ignore_notfound_exc(
                cls.creds_client.delete_credential, credential['id'])

        # Delete each domain at the end of the test, but each domain must be
        # disabled first.
        for domain in cls.domains:
            test_utils.call_and_ignore_notfound_exc(
                cls.domains_client.update_domain, domain['id'], enabled=False)
            test_utils.call_and_ignore_notfound_exc(
                cls.domains_client.delete_domain, domain['id'])

        for group in cls.groups:
            test_utils.call_and_ignore_notfound_exc(
                cls.groups_client.delete_group, group['id'])

        for policy in cls.policies:
            test_utils.call_and_ignore_notfound_exc(
                cls.policies_client.delete_policy, policy['id'])

        for project in cls.projects:
            test_utils.call_and_ignore_notfound_exc(
                cls.projects_client.delete_project, project['id'])

        for region in cls.regions:
            test_utils.call_and_ignore_notfound_exc(
                cls.regions_client.delete_region, region['id'])

        for trust in cls.trusts:
            test_utils.call_and_ignore_notfound_exc(
                cls.trusts_client.delete_trust, trust['id'])

        for token in cls.tokens:
            test_utils.call_and_ignore_notfound_exc(
                cls.identity_client.delete_token, token)

        super(BaseIdentityV3RbacTest, cls).resource_cleanup()

    @classmethod
    def setup_test_endpoint(cls, service=None):
        """Creates a service and an endpoint for test."""
        interface = 'public'
        url = data_utils.rand_url()
        region_name = data_utils.rand_name(
            cls.__name__ + '-region')
        # Endpoint creation requires a service
        if service is None:
            service = cls.setup_test_service()
        params = {
            'service_id': service['id'],
            'region': region_name,
            'interface': interface,
            'url': url
        }

        endpoint = cls.endpoints_client.create_endpoint(**params)['endpoint']
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.regions_client.delete_region, endpoint['region'])
        cls.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            cls.endpoints_client.delete_endpoint, endpoint['id'])

        return endpoint

    @classmethod
    def setup_test_credential(cls, user=None):
        """Creates a credential for test."""
        keys = [data_utils.rand_uuid_hex(),
                data_utils.rand_uuid_hex()]
        blob = '{"access": "%s", "secret": "%s"}' % (keys[0], keys[1])

        credential = cls.creds_client.create_credential(
            user_id=user['id'],
            project_id=user['project_id'],
            blob=blob,
            type='ec2')['credential']
        cls.credentials.append(credential)

        return credential

    @classmethod
    def setup_test_domain(cls):
        """Set up a test domain."""
        domain = cls.domains_client.create_domain(
            name=data_utils.rand_name(cls.__name__),
            description=data_utils.rand_name(
                cls.__name__ + '-desc'))['domain']
        cls.domains.append(domain)

        return domain

    @classmethod
    def setup_test_group(cls):
        """Creates a group for test."""
        name = data_utils.rand_name(cls.__name__ + '-test_group')
        group = cls.groups_client.create_group(name=name)['group']
        cls.groups.append(group)

        return group

    @classmethod
    def setup_test_policy(cls):
        """Creates a policy for test."""
        blob = data_utils.rand_name(cls.__name__ + '-test_blob')
        policy_type = data_utils.rand_name(
            cls.__name__ + '-policy_type')

        policy = cls.policies_client.create_policy(
            blob=blob,
            policy=policy_type,
            type="application/json")['policy']
        cls.policies.append(policy)

        return policy

    @classmethod
    def setup_test_project(cls):
        """Set up a test project."""
        project = cls.projects_client.create_project(
            name=data_utils.rand_name(
                cls.__name__),
            description=data_utils.rand_name(
                cls.__name__ + '-desc'))['project']
        cls.projects.append(project)

        return project

    @classmethod
    def setup_test_region(cls):
        """Creates a region for test."""
        description = data_utils.rand_name(
            cls.__name__ + '-test_region_desc')
        id = data_utils.rand_name(cls.__name__)

        region = cls.regions_client.create_region(
            id=id,
            description=description)['region']
        cls.regions.append(region)

        return region

    @classmethod
    def setup_test_trust(cls, trustee_user_id, trustor_user_id, **kwargs):
        """Setup a test trust."""
        trust = cls.trusts_client.create_trust(
            trustee_user_id=trustee_user_id, trustor_user_id=trustor_user_id,
            impersonation=False, **kwargs)['trust']
        cls.trusts.append(trust)

        return trust

    @classmethod
    def setup_test_token(cls, user_id, password):
        """Set up a test token."""
        token = cls.token_client.auth(user_id=user_id,
                                      password=password).response
        token_id = token['x-subject-token']
        cls.tokens.append(token_id)
        return token_id
