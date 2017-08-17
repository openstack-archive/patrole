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

import abc
import six
import sys
import time

from oslo_log import log as logging
from oslo_utils import excutils

from tempest import clients
from tempest.common import credentials_factory as credentials
from tempest import config

from patrole_tempest_plugin import rbac_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacUtils(object):
    """Utility class responsible for switching os_primary role.

    This class is responsible for overriding the value of the primary Tempest
    credential's role (i.e. "os_primary" role). By doing so, it is possible to
    seamlessly swap between admin credentials, needed for setup and clean up,
    and primary credentials, needed to perform the API call which does
    policy enforcement. The primary credentials always cycle between roles
    defined by ``CONF.identity.admin_role`` and `CONF.patrole.rbac_test_role``.
    """

    def __init__(self, test_obj):
        """Constructor for ``RbacUtils``.

        :param test_obj: An instance of `tempest.test.BaseTestCase`.
        """
        # Intialize the admin roles_client to perform role switching.
        admin_mgr = clients.Manager(
            credentials.get_configured_admin_credentials())
        if test_obj.get_identity_version() == 'v3':
            admin_roles_client = admin_mgr.roles_v3_client
        else:
            admin_roles_client = admin_mgr.roles_client

        self.admin_roles_client = admin_roles_client
        self.switch_role(test_obj, toggle_rbac_role=False)

    # References the last value of `toggle_rbac_role` that was passed to
    # `switch_role`. Used for ensuring that `switch_role` is correctly used
    # in a test file, so that false positives are prevented. The key used
    # to index into the dictionary is the module path plus class name, which is
    # unique.
    switch_role_history = {}
    admin_role_id = None
    rbac_role_id = None

    def switch_role(self, test_obj, toggle_rbac_role=False):
        """Switch the role used by `os_primary` Tempest credentials.

        Switch the role used by `os_primary` credentials to:
          * admin if `toggle_rbac_role` is False
          * `CONF.patrole.rbac_test_role` if `toggle_rbac_role` is True

        :param test_obj: test object of type tempest.lib.base.BaseTestCase
        :param toggle_rbac_role: role to switch `os_primary` Tempest creds to
        """
        self.user_id = test_obj.os_primary.credentials.user_id
        self.project_id = test_obj.os_primary.credentials.tenant_id
        self.token = test_obj.os_primary.auth_provider.get_token()

        LOG.debug('Switching role to: %s.', toggle_rbac_role)
        role_already_present = False

        try:
            if not all([self.admin_role_id, self.rbac_role_id]):
                self._get_roles_by_name()

            self._validate_switch_role(test_obj, toggle_rbac_role)

            target_role = (
                self.rbac_role_id if toggle_rbac_role else self.admin_role_id)
            role_already_present = self._list_and_clear_user_roles_on_project(
                target_role)

            # Do not switch roles if `target_role` already exists.
            if not role_already_present:
                self._create_user_role_on_project(target_role)
        except Exception as exp:
            with excutils.save_and_reraise_exception():
                LOG.exception(exp)
        finally:
            test_obj.os_primary.auth_provider.clear_auth()
            # Fernet tokens are not subsecond aware so sleep to ensure we are
            # passing the second boundary before attempting to authenticate.
            # Only sleep if a token revocation occurred as a result of role
            # switching. This will optimize test runtime in the case where
            # ``[identity] admin_role`` == ``[rbac] rbac_test_role``.
            if not role_already_present:
                time.sleep(1)
            test_obj.os_primary.auth_provider.set_auth()

    def _get_roles_by_name(self):
        available_roles = self.admin_roles_client.list_roles()
        admin_role_id = rbac_role_id = None

        for role in available_roles['roles']:
            if role['name'] == CONF.patrole.rbac_test_role:
                rbac_role_id = role['id']
            if role['name'] == CONF.identity.admin_role:
                admin_role_id = role['id']

        if not all([admin_role_id, rbac_role_id]):
            msg = ("Roles defined by `[patrole] rbac_test_role` and "
                   "`[identity] admin_role` must be defined in the system.")
            raise rbac_exceptions.RbacResourceSetupFailed(msg)

        self.admin_role_id = admin_role_id
        self.rbac_role_id = rbac_role_id

    def _create_user_role_on_project(self, role_id):
        self.admin_roles_client.create_user_role_on_project(
            self.project_id, self.user_id, role_id)

    def _list_and_clear_user_roles_on_project(self, role_id):
        roles = self.admin_roles_client.list_user_roles_on_project(
            self.project_id, self.user_id)['roles']
        role_ids = [role['id'] for role in roles]

        # NOTE(felipemonteiro): We do not use ``role_id in role_ids`` here to
        # avoid over-permission errors: if the current list of roles on the
        # project includes "admin" and "Member", and we are switching to the
        # "Member" role, then we must delete the "admin" role. Thus, we only
        # return early if the user's roles on the project are an exact match.
        if [role_id] == role_ids:
            return True

        for role in roles:
            self.admin_roles_client.delete_role_from_user_on_project(
                self.project_id, self.user_id, role['id'])

        return False

    def _validate_switch_role(self, test_obj, toggle_rbac_role):
        """Validates that the test role passed to `switch_role` is legal.

        Throws an error for the following improper usages of `switch_role`:
            * `switch_role` is not called with a boolean value
            * `switch_role` is never called inside a test, except in tearDown
            * `switch_role` is called with the same boolean value twice

        If a `skipException` is thrown then this is a legitimate reason why
        `switch_role` is not called.
        """
        if not isinstance(toggle_rbac_role, bool):
            raise rbac_exceptions.RbacResourceSetupFailed(
                '`toggle_rbac_role` must be a boolean value.')

        # The unique key is the combination of module path plus class name.
        class_name = test_obj.__name__ if isinstance(test_obj, type) else \
            test_obj.__class__.__name__
        module_name = test_obj.__module__
        key = '%s.%s' % (module_name, class_name)

        self.switch_role_history.setdefault(key, None)

        if self.switch_role_history[key] == toggle_rbac_role:
            # If an exception was thrown, like a skipException or otherwise,
            # then this is a legitimate reason why `switch_role` was not
            # called, so only raise an exception if no current exception is
            # being handled.
            if sys.exc_info()[0] is None:
                self.switch_role_history[key] = False
                error_message = '`toggle_rbac_role` must not be called with '\
                    'the same bool value twice. Make sure that you included '\
                    'a rbac_utils.switch_role method call inside the test.'
                LOG.error(error_message)
                raise rbac_exceptions.RbacResourceSetupFailed(error_message)
        else:
            self.switch_role_history[key] = toggle_rbac_role

    def _get_roles(self):
        available_roles = self.admin_roles_client.list_roles()
        admin_role_id = rbac_role_id = None

        for role in available_roles['roles']:
            if role['name'] == CONF.patrole.rbac_test_role:
                rbac_role_id = role['id']
            if role['name'] == CONF.identity.admin_role:
                admin_role_id = role['id']

        if not admin_role_id or not rbac_role_id:
            msg = "Role with name 'admin' does not exist in the system."\
                if not admin_role_id else "Role defined by rbac_test_role "\
                "does not exist in the system."
            raise rbac_exceptions.RbacResourceSetupFailed(msg)

        self.admin_role_id = admin_role_id
        self.rbac_role_id = rbac_role_id


def is_admin():
    """Verifies whether the current test role equals the admin role.

    :returns: True if ``rbac_test_role`` is the admin role.
    """
    return CONF.patrole.rbac_test_role == CONF.identity.admin_role


@six.add_metaclass(abc.ABCMeta)
class RbacAuthority(object):
    # TODO(rb560u): Add documentation explaining what this class is for

    @abc.abstractmethod
    def allowed(self, rule_name, role):
        """Determine whether the role should be able to perform the API"""
        return
