#    Copyright 2017 AT&T Inc.
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

import mock

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation as rbac_rv

from tempest.lib import exceptions

from tempest.tests import base


class RBACRuleValidationTest(base.TestCase):
    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_happy_path(self, mock_auth):
        decorator = rbac_rv.action("", "")
        mock_function = mock.Mock()
        mock_args = mock.MagicMock(**{
            'auth_provider.credentials.tenant_id': 'tenant_id'
        })
        wrapper = decorator(mock_function)
        wrapper((mock_args))
        self.assertTrue(mock_function.called)

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_forbidden(self, mock_auth):
        decorator = rbac_rv.action("", "")
        mock_function = mock.Mock()
        mock_function.side_effect = exceptions.Forbidden
        wrapper = decorator(mock_function)
        mock_args = mock.MagicMock(**{
            'auth_provider.credentials.tenant_id': 'tenant_id'
        })

        self.assertRaises(exceptions.Forbidden, wrapper, mock_args)

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_rbac_action_failed(self, mock_auth):
        decorator = rbac_rv.action("", "")
        mock_function = mock.Mock()
        mock_function.side_effect = rbac_exceptions.RbacActionFailed
        mock_args = mock.MagicMock(**{
            'auth_provider.credentials.tenant_id': 'tenant_id'
        })

        wrapper = decorator(mock_function)
        self.assertRaises(exceptions.Forbidden, wrapper, mock_args)

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_not_allowed(self, mock_auth):
        decorator = rbac_rv.action("", "")

        mock_function = mock.Mock()
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        mock_args = mock.MagicMock(**{
            'auth_provider.credentials.tenant_id': 'tenant_id'
        })

        self.assertRaises(rbac_exceptions.RbacOverPermission, wrapper,
                          mock_args)

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_forbidden_not_allowed(self, mock_auth):
        decorator = rbac_rv.action("", "")

        mock_function = mock.Mock()
        mock_function.side_effect = exceptions.Forbidden
        mock_args = mock.MagicMock(**{
            'auth_provider.credentials.tenant_id': 'tenant_id'
        })
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        self.assertIsNone(wrapper(mock_args))

    @mock.patch('patrole_tempest_plugin.rbac_auth.RbacAuthority')
    def test_RBAC_rv_rbac_action_failed_not_allowed(self, mock_auth):
        decorator = rbac_rv.action("", "")

        mock_function = mock.Mock()
        mock_function.side_effect = rbac_exceptions.RbacActionFailed
        wrapper = decorator(mock_function)

        mock_permission = mock.Mock()
        mock_permission.get_permission.return_value = False
        mock_auth.return_value = mock_permission

        mock_args = mock.MagicMock(**{
            'auth_provider.credentials.tenant_id': 'tenant_id'
        })

        self.assertIsNone(wrapper(mock_args))
