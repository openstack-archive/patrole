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

from contextlib import contextmanager
import sys
import time

from oslo_log import log as logging
from oslo_log import versionutils
from oslo_utils import excutils

from tempest import clients
from tempest.common import credentials_factory as credentials
from tempest import config

from patrole_tempest_plugin import rbac_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacUtils(object):
    """Utility class responsible for switching ``os_primary`` role.

    This class is responsible for overriding the value of the primary Tempest
    credential's role (i.e. ``os_primary`` role). By doing so, it is possible
    to seamlessly swap between admin credentials, needed for setup and clean
    up, and primary credentials, needed to perform the API call which does
    policy enforcement. The primary credentials always cycle between roles
    defined by ``CONF.identity.admin_role`` and
    ``CONF.patrole.rbac_test_role``.
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
        self._override_role(test_obj, False)

    admin_role_id = None
    rbac_role_id = None

    @contextmanager
    def override_role(self, test_obj):
        """Override the role used by ``os_primary`` Tempest credentials.

        Temporarily change the role used by ``os_primary`` credentials to:

        * ``[patrole] rbac_test_role`` before test execution
        * ``[identity] admin_role`` after test execution

        Automatically switches to admin role after test execution.

        :param test_obj: Instance of ``tempest.test.BaseTestCase``.
        :returns: None

        .. warning::

            This function can alter user roles for pre-provisioned credentials.
            Work is underway to safely clean up after this function.

        Example::

            @rbac_rule_validation.action(service='test',
                                         rule='a:test:rule')
            def test_foo(self):
                # Allocate test-level resources here.
                with self.rbac_utils.override_role(self):
                    # The role for `os_primary` has now been overridden. Within
                    # this block, call the API endpoint that enforces the
                    # expected policy specified by "rule" in the decorator.
                    self.foo_service.bar_api_call()
                # The role is switched back to admin automatically. Note that
                # if the API call above threw an exception, any code below this
                # point in the test is not executed.
        """
        test_obj._set_override_role_called()
        self._override_role(test_obj, True)
        try:
            # Execute the test.
            yield
        finally:
            # Check whether an exception was raised. If so, remember that
            # for future validation.
            exc = sys.exc_info()[0]
            if exc is not None:
                test_obj._set_override_role_caught_exc()
            # This code block is always executed, no matter the result of the
            # test. Automatically switch back to the admin role for test clean
            # up.
            self._override_role(test_obj, False)

    def _override_role(self, test_obj, toggle_rbac_role=False):
        """Private helper for overriding ``os_primary`` Tempest credentials.

        :param test_obj: instance of :py:class:`tempest.test.BaseTestCase`
        :param toggle_rbac_role: Boolean value that controls the role that
            overrides default role of ``os_primary`` credentials.
            * If True: role is set to ``[patrole] rbac_test_role``
            * If False: role is set to ``[identity] admin_role``
        """
        self.user_id = test_obj.os_primary.credentials.user_id
        self.project_id = test_obj.os_primary.credentials.tenant_id
        self.token = test_obj.os_primary.auth_provider.get_token()

        LOG.debug('Overriding role to: %s.', toggle_rbac_role)
        role_already_present = False

        try:
            if not all([self.admin_role_id, self.rbac_role_id]):
                self._get_roles_by_name()

            target_role = (
                self.rbac_role_id if toggle_rbac_role else self.admin_role_id)
            role_already_present = self._list_and_clear_user_roles_on_project(
                target_role)

            # Do not override roles if `target_role` already exists.
            if not role_already_present:
                self._create_user_role_on_project(target_role)
        except Exception as exp:
            with excutils.save_and_reraise_exception():
                LOG.exception(exp)
        finally:
            auth_providers = test_obj.get_auth_providers()
            for provider in auth_providers:
                provider.clear_auth()
            # Fernet tokens are not subsecond aware so sleep to ensure we are
            # passing the second boundary before attempting to authenticate.
            # Only sleep if a token revocation occurred as a result of role
            # overriding. This will optimize test runtime in the case where
            # ``[identity] admin_role`` == ``[patrole] rbac_test_role``.
            if not role_already_present:
                time.sleep(1)

            for provider in auth_providers:
                provider.set_auth()

    def _get_roles_by_name(self):
        available_roles = self.admin_roles_client.list_roles()['roles']
        role_map = {r['name']: r['id'] for r in available_roles}
        LOG.debug('Available roles: %s', list(role_map.keys()))

        admin_role_id = role_map.get(CONF.identity.admin_role)
        rbac_role_id = role_map.get(CONF.patrole.rbac_test_role)

        if not all([admin_role_id, rbac_role_id]):
            missing_roles = []
            msg = ("Could not find `[patrole] rbac_test_role` or "
                   "`[identity] admin_role`, both of which are required for "
                   "RBAC testing.")
            if not admin_role_id:
                missing_roles.append(CONF.identity.admin_role)
            if not rbac_role_id:
                missing_roles.append(CONF.patrole.rbac_test_role)
            msg += " Following roles were not found: %s." % (
                ", ".join(missing_roles))
            msg += " Available roles: %s." % ", ".join(list(role_map.keys()))
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


class RbacUtilsMixin(object):
    """Mixin class to be used alongside an instance of
    :py:class:`tempest.test.BaseTestCase`.

    Should be used to perform Patrole class setup for a base RBAC class. Child
    classes should not use this mixin.

    Example::

        class BaseRbacTest(rbac_utils.RbacUtilsMixin, base.BaseV2ComputeTest):

            @classmethod
            def skip_checks(cls):
                super(BaseRbacTest, cls).skip_checks()
                cls.skip_rbac_checks()

            @classmethod
            def setup_clients(cls):
                super(BaseRbacTest, cls).setup_clients()
                cls.setup_rbac_utils()
    """

    # Shows if override_role was called.
    __override_role_called = False
    # Shows if exception raised during override_role.
    __override_role_caught_exc = False

    @classmethod
    def get_auth_providers(cls):
        """Returns list of auth_providers used within test.

        Tests may redefine this method to include their own or third party
        client auth_providers.
        """
        return [cls.os_primary.auth_provider]

    @classmethod
    def skip_rbac_checks(cls):
        if not CONF.patrole.enable_rbac:
            deprecation_msg = ("The `[patrole].enable_rbac` option is "
                               "deprecated and will be removed in the S "
                               "release. Patrole tests will always be enabled "
                               "following installation of the Patrole Tempest "
                               "plugin. Use a regex to skip tests")
            versionutils.report_deprecated_feature(LOG, deprecation_msg)
            raise cls.skipException(
                'Patrole testing not enabled so skipping %s.' % cls.__name__)

    @classmethod
    def setup_rbac_utils(cls):
        cls.rbac_utils = RbacUtils(cls)

    def _set_override_role_called(self):
        """Helper for tracking whether ``override_role`` was called."""
        self.__override_role_called = True

    def _set_override_role_caught_exc(self):
        """Helper for tracking whether exception was thrown inside
        ``override_role``.
        """
        self.__override_role_caught_exc = True

    def _validate_override_role_called(self):
        """Idempotently validate that ``override_role`` is called and reset
        its value to False for sequential tests.
        """
        was_called = self.__override_role_called
        self.__override_role_called = False
        return was_called

    def _validate_override_role_caught_exc(self):
        """Idempotently validate that exception was caught inside
        ``override_role``, so that, by process of elimination, it can be
        determined whether one was thrown outside (which is invalid).
        """
        caught_exception = self.__override_role_caught_exc
        self.__override_role_caught_exc = False
        return caught_exception


def is_admin():
    """Verifies whether the current test role equals the admin role.

    :returns: True if ``rbac_test_role`` is the admin role.
    """
    # TODO(felipemonteiro): Make this more robust via a context is admin
    # lookup.
    return CONF.patrole.rbac_test_role == CONF.identity.admin_role
