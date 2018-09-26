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

"""Fixtures for Patrole tests."""
from __future__ import absolute_import

from contextlib import contextmanager
import fixtures
import mock
import time

from tempest import clients
from tempest.common import credentials_factory as credentials
from tempest import config
from tempest import test

from patrole_tempest_plugin import rbac_utils


CONF = config.CONF


class ConfPatcher(fixtures.Fixture):
    """Fixture to patch and restore global CONF. Adopted from Nova.

    This also resets overrides for everything that is patched during
    its teardown.
    """

    def __init__(self, **kwargs):
        """Constructor

        :params group: if specified all config options apply to that group.
        :params **kwargs: the rest of the kwargs are processed as a
            set of key/value pairs to be set as configuration override.
        """
        super(ConfPatcher, self).__init__()
        self.group = kwargs.pop('group', None)
        self.args = kwargs

    def setUp(self):
        super(ConfPatcher, self).setUp()
        for k, v in self.args.items():
            self.addCleanup(CONF.clear_override, k, self.group)
            CONF.set_override(k, v, self.group)


class RbacUtilsFixture(fixtures.Fixture):
    """Fixture for `RbacUtils` class."""

    USER_ID = mock.sentinel.user_id
    PROJECT_ID = mock.sentinel.project_id

    def setUp(self):
        super(RbacUtilsFixture, self).setUp()

        self.useFixture(ConfPatcher(rbac_test_roles=['member'],
                                    group='patrole'))
        self.useFixture(ConfPatcher(
            admin_role='admin', auth_version='v3', group='identity'))
        self.useFixture(ConfPatcher(
            api_v3=True, group='identity-feature-enabled'))

        test_obj_kwargs = {
            'os_primary.credentials.user_id': self.USER_ID,
            'os_primary.credentials.tenant_id': self.PROJECT_ID,
            'os_primary.credentials.project_id': self.PROJECT_ID,
        }
        self.mock_test_obj = mock.Mock(
            __name__='patrole_unit_test', spec=test.BaseTestCase,
            os_primary=mock.Mock(),
            get_auth_providers=mock.Mock(return_value=[mock.Mock()]),
            **test_obj_kwargs)

        # Mock out functionality that can't be used by unit tests. Mocking out
        # time.sleep is a test optimization.
        self.mock_time = mock.patch.object(
            rbac_utils, 'time', __name__='mock_time', spec=time).start()
        mock.patch.object(credentials, 'get_configured_admin_credentials',
                          spec=object).start()
        mock_admin_mgr = mock.patch.object(
            clients, 'Manager', spec=clients.Manager,
            roles_v3_client=mock.Mock(), roles_client=mock.Mock()).start()
        self.admin_roles_client = mock_admin_mgr.return_value.roles_v3_client

        self.set_roles(['admin', 'member'], [])

    def override_role(self, *role_toggles):
        """Instantiate `rbac_utils.RbacUtils` and call `override_role`.

        Create an instance of `rbac_utils.RbacUtils` and call `override_role`
        for each boolean value in `role_toggles`. The number of calls to
        `override_role` is always 1 + len(`role_toggles`) because the
        `rbac_utils.RbacUtils` constructor automatically calls `override_role`.

        :param role_toggles: the list of boolean values iterated over and
            passed to `override_role`.
        """
        _rbac_utils = rbac_utils.RbacUtils(self.mock_test_obj)

        for role_toggle in role_toggles:
            _rbac_utils._override_role(self.mock_test_obj, role_toggle)
            # NOTE(felipemonteiro): Simulate that a role switch has occurred
            # by updating the user's current role to the new role. This means
            # that all API actions involved during a role switch -- listing,
            # deleting and adding roles -- are executed, making it easier to
            # assert that mock calls were called as expected.
            new_role = 'member' if role_toggle else 'admin'
            self.set_roles(['admin', 'member'], [new_role])

    @contextmanager
    def real_override_role(self, test_obj):
        """Actual call to ``override_role``.

        Useful for ensuring all the necessary mocks are performed before
        the method in question is called.
        """
        _rbac_utils = rbac_utils.RbacUtils(test_obj)
        with _rbac_utils.override_role(test_obj):
            yield

    def set_roles(self, roles, roles_on_project=None):
        """Set the list of available roles in the system.

        :param roles: List of roles returned by ``list_roles``.
        :param roles_on_project: List of roles returned by
            ``list_user_roles_on_project``.
        :returns: None.
        """
        if not roles_on_project:
            roles_on_project = []
        if not isinstance(roles, list):
            roles = [roles]
        if not isinstance(roles_on_project, list):
            roles_on_project = [roles_on_project]

        available_roles = {
            'roles': [{'name': role, 'id': '%s_id' % role} for role in roles]
        }
        available_project_roles = {
            'roles': [{'name': role, 'id': '%s_id' % role}
                      for role in roles_on_project]
        }

        self.admin_roles_client.list_roles.return_value = available_roles
        self.admin_roles_client.list_user_roles_on_project.return_value = (
            available_project_roles)
