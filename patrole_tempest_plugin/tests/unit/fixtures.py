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

import fixtures
import mock

from tempest import config

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
    """Fixture for RbacUtils class."""

    USER_ID = mock.sentinel.user_id
    PROJECT_ID = mock.sentinel.project_id

    def __init__(self, **kwargs):
        super(RbacUtilsFixture, self).__init__()
        self.available_roles = None

    def setUp(self):
        super(RbacUtilsFixture, self).setUp()

        self.useFixture(ConfPatcher(rbac_test_role='member', group='rbac'))
        self.useFixture(ConfPatcher(
            admin_role='admin', auth_version='v3', group='identity'))

        test_obj_kwargs = {
            'os_primary.credentials.user_id': self.USER_ID,
            'os_primary.credentials.tenant_id': self.PROJECT_ID,
            'os_primary.credentials.project_id': self.PROJECT_ID,
            'get_identity_version.return_value': 'v3'
        }
        self.mock_test_obj = mock.Mock(**test_obj_kwargs)
        self.mock_time = mock.patch.object(rbac_utils, 'time').start()

        self.roles_v3_client = (
            self.mock_test_obj.get_client_manager.return_value.roles_v3_client)

    def switch_role(self, *role_toggles):
        """Instantiate `rbac_utils.RbacUtils` and call `switch_role`.

        Create an instance of `rbac_utils.RbacUtils` and call `switch_role`
        for each boolean value in `role_toggles`. The number of calls to
        `switch_role` is always 1 + len(role_toggles) because the
        `rbac_utils.RbacUtils` constructor automatically calls `switch_role`.

        :param role_toggles: the list of boolean values iterated over and
            passed to `switch_role`.
        """
        if not self.available_roles:
            self.set_roles('admin', 'member')

        self.fake_rbac_utils = rbac_utils.RbacUtils(self.mock_test_obj)
        for role_toggle in role_toggles:
            self.fake_rbac_utils.switch_role(self.mock_test_obj, role_toggle)

    def set_roles(self, *roles):
        """Set the list of available roles in the system to `roles`."""
        self.available_roles = {
            'roles': [{'name': role, 'id': '%s_id' % role} for role in roles]
        }
        self.roles_v3_client.list_user_roles_on_project.return_value =\
            self.available_roles
        self.roles_v3_client.list_roles.return_value = self.available_roles
