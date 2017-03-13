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

import six
import time

from tempest.common import credentials_factory
from tempest import config
from tempest.test import BaseTestCase

from oslo_log import log as logging

from patrole_tempest_plugin import rbac_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,
                                                                 **kwargs)
        return cls._instances[cls]


@six.add_metaclass(Singleton)
class RbacUtils(object):

    def __init__(cls):
        creds_provider = credentials_factory.get_credentials_provider(
            name=__name__,
            force_tenant_isolation=True,
            identity_version=BaseTestCase.get_identity_version())

        cls.creds_client = creds_provider.creds_client
        cls.available_roles = cls.creds_client.roles_client.list_roles()
        cls.admin_role_id = cls.rbac_role_id = None
        for item in cls.available_roles['roles']:
            if item['name'] == CONF.rbac.rbac_test_role:
                cls.rbac_role_id = item['id']
            if item['name'] == 'admin':
                cls.admin_role_id = item['id']

    def switch_role(cls, test_obj, switchToRbacRole=None):
        LOG.debug('Switching role to: %s', switchToRbacRole)
        # Check if admin and rbac roles exist.
        if not cls.admin_role_id or not cls.rbac_role_id:
            msg = ("Defined 'rbac_role' or 'admin' role does not exist"
                   " in the system.")
            raise rbac_exceptions.RbacResourceSetupFailed(msg)

        if not isinstance(switchToRbacRole, bool):
            msg = ("Wrong value for parameter 'switchToRbacRole' is passed."
                   " It should be either 'True' or 'False'.")
            raise rbac_exceptions.RbacResourceSetupFailed(msg)

        try:
            user_id = test_obj.auth_provider.credentials.user_id
            project_id = test_obj.auth_provider.credentials.tenant_id

            cls._clear_user_roles(user_id, project_id)

            if switchToRbacRole:
                cls.creds_client.roles_client.create_user_role_on_project(
                    project_id, user_id, cls.rbac_role_id)
            else:
                cls.creds_client.roles_client.create_user_role_on_project(
                    project_id, user_id, cls.admin_role_id)

        except Exception as exp:
            LOG.error(exp)
            raise

        finally:
            if BaseTestCase.get_identity_version() != 'v3':
                test_obj.auth_provider.clear_auth()
                # Sleep to avoid 401 errors caused by rounding in timing of
                # fernet token creation.
                time.sleep(1)
                test_obj.auth_provider.set_auth()

    def _clear_user_roles(cls, user_id, tenant_id):
        roles = cls.creds_client.roles_client.list_user_roles_on_project(
            tenant_id, user_id)['roles']

        for role in roles:
            cls.creds_client.roles_client.delete_role_from_user_on_project(
                tenant_id, user_id, role['id'])

rbac_utils = RbacUtils
