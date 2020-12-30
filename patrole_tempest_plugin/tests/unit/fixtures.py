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
from unittest import mock

import fixtures
import time

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


class FakeBaseRbacTest(rbac_utils.RbacUtilsMixin, test.BaseTestCase):
    credentials = []
    os_primary = None

    def runTest(self):
        pass


class RbacUtilsMixinFixture(fixtures.Fixture):
    """Fixture for `RbacUtils` class."""

    USER_ID = mock.sentinel.user_id
    PROJECT_ID = mock.sentinel.project_id

    def __init__(self, do_reset_mocks=True, rbac_test_roles=None):
        self._do_reset_mocks = do_reset_mocks
        self._rbac_test_roles = rbac_test_roles or ['member']

    def patchobject(self, target, attribute, *args, **kwargs):
        p = mock.patch.object(target, attribute, *args, **kwargs)
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def setUp(self):
        super(RbacUtilsMixinFixture, self).setUp()

        self.useFixture(ConfPatcher(rbac_test_roles=self._rbac_test_roles,
                                    group='patrole'))
        self.useFixture(ConfPatcher(
            admin_role='admin', auth_version='v3', group='identity'))
        self.useFixture(ConfPatcher(
            api_v3=True, group='identity-feature-enabled'))

        # Mock out functionality that can't be used by unit tests. Mocking out
        # time.sleep is a test optimization.
        self.mock_time = self.patchobject(rbac_utils, 'time',
                                          __name__='mock_time', spec=time)

        test_obj_kwargs = {
            'credentials.user_id': self.USER_ID,
            'credentials.tenant_id': self.PROJECT_ID,
            'credentials.project_id': self.PROJECT_ID,
        }

        class FakeRbacTest(FakeBaseRbacTest):
            os_primary = mock.Mock()
            os_admin = mock.Mock()

        FakeRbacTest.os_primary.configure_mock(**test_obj_kwargs)

        self.admin_roles_client = FakeRbacTest.os_admin.roles_v3_client
        self.admin_roles_client.list_all_role_inference_rules.return_value = {
            "role_inferences": [
                {
                    "implies": [{"id": "reader_id", "name": "reader"}],
                    "prior_role": {"id": "member_id", "name": "member"}
                },
                {
                    "implies": [{"id": "member_id", "name": "member"}],
                    "prior_role": {"id": "admin_id", "name": "admin"}
                }
            ]
        }

        default_roles = {'admin', 'member', 'reader'}.union(
            set(self._rbac_test_roles))
        self.set_roles(list(default_roles), [])

        FakeRbacTest.setUpClass()
        self.test_obj = FakeRbacTest()
        if self._do_reset_mocks:
            self.admin_roles_client.reset_mock()
            self.test_obj.os_primary.reset_mock()
            self.test_obj.os_admin.reset_mock()
            self.mock_time.reset_mock()

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
