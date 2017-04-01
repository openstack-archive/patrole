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

import sys
import testtools
import time

from oslo_log import log as logging
import oslo_utils.uuidutils as uuid_utils
import six

from tempest import config

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

    # References the last value of `switch_to_rbac_role` that was passed to
    # `switch_role`. Used for ensuring that `switch_role` is correctly used
    # in a test file, so that false positives are prevented. The key used
    # to index into the dictionary is the class name, which is unique.
    switch_role_history = {}
    admin_role_id = None
    rbac_role_id = None

    def switch_role(self, test_obj, switchToRbacRole=False):
        self.user_id = test_obj.auth_provider.credentials.user_id
        self.project_id = test_obj.auth_provider.credentials.tenant_id
        self.token = test_obj.auth_provider.get_token()
        self.identity_version = test_obj.get_identity_version()

        if self.identity_version.endswith('v3'):
            self.roles_client = test_obj.os_admin.roles_v3_client
        else:
            self.roles_client = test_obj.os_admin.roles_client

        LOG.debug('Switching role to: %s', switchToRbacRole)

        try:
            if not self.admin_role_id or not self.rbac_role_id:
                self._get_roles()

            rbac_utils._validate_switch_role(self, test_obj, switchToRbacRole)

            if switchToRbacRole:
                self._add_role_to_user(self.rbac_role_id)
            else:
                self._add_role_to_user(self.admin_role_id)
        except Exception as exp:
            LOG.error(exp)
            raise
        finally:
            # NOTE(felipemonteiro): These two comments below are copied from
            # tempest.api.identity.v2/v3.test_users.
            #
            # Reset auth again to verify the password restore does work.
            # Clear auth restores the original credentials and deletes
            # cached auth data.
            test_obj.auth_provider.clear_auth()
            # Fernet tokens are not subsecond aware and Keystone should only be
            # precise to the second. Sleep to ensure we are passing the second
            # boundary before attempting to authenticate. If token is of type
            # uuid, then do not sleep.
            if not uuid_utils.is_uuid_like(self.token):
                time.sleep(1)
            test_obj.auth_provider.set_auth()

    def _add_role_to_user(self, role_id):
        role_already_present = self._clear_user_roles(role_id)
        if role_already_present:
            return

        self.roles_client.create_user_role_on_project(
            self.project_id, self.user_id, role_id)

    def _clear_user_roles(self, role_id):
        roles = self.roles_client.list_user_roles_on_project(
            self.project_id, self.user_id)['roles']

        # If the user already has the role that is required, return early.
        role_ids = [role['id'] for role in roles]
        if role_ids == [role_id]:
            return True

        for role in roles:
            self.roles_client.delete_role_from_user_on_project(
                self.project_id, self.user_id, role['id'])

        return False

    def _validate_switch_role(self, test_obj, switchToRbacRole):
        """Validates that the rbac role passed to `switch_role` is legal.

        Throws an error for the following improper usages of `switch_role`:
            * `switch_role` is not called with a boolean value
            * `switch_role` is never called in a test file, except in tearDown
            * `switch_role` is called with the same boolean value twice
        """
        if not isinstance(switchToRbacRole, bool):
            raise rbac_exceptions.RbacResourceSetupFailed(
                'switchToRbacRole must be a boolean value.')

        key = test_obj.__name__ if isinstance(test_obj, type) else \
            test_obj.__class__.__name__
        self.switch_role_history.setdefault(key, None)

        if self.switch_role_history[key] == switchToRbacRole:
            # If the test was skipped, then this is a legitimate use case,
            # so do not throw an exception.
            exc_value = sys.exc_info()[1]
            if not isinstance(exc_value, testtools.TestCase.skipException):
                self.switch_role_history[key] = False
                error_message = '`switchToRbacRole` must not be called with '\
                    'the same bool value twice. Make sure that you included '\
                    'a rbac_utils.switch_role method call inside the test.'
                LOG.error(error_message)
                raise rbac_exceptions.RbacResourceSetupFailed(error_message)
        else:
            self.switch_role_history[key] = switchToRbacRole

    def _get_roles(self):
        available_roles = self.roles_client.list_roles()
        admin_role_id = rbac_role_id = None

        for role in available_roles['roles']:
            if role['name'] == CONF.rbac.rbac_test_role:
                rbac_role_id = role['id']
            if role['name'] == 'admin':
                admin_role_id = role['id']

        if not admin_role_id or not rbac_role_id:
            msg = "Role with name 'admin' does not exist in the system."\
                if not admin_role_id else "Role defined by rbac_test_role "\
                "does not exist in the system."
            raise rbac_exceptions.RbacResourceSetupFailed(msg)

        self.admin_role_id = admin_role_id
        self.rbac_role_id = rbac_role_id

rbac_utils = RbacUtils
