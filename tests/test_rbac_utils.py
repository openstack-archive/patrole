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

import json
import mock

from tempest.tests import base

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_utils as utils


class RBACUtilsTest(base.TestCase):
    def setUp(self):
        super(RBACUtilsTest, self).setUp()
        self.rbac_utils = utils.RbacUtils

    get_response = 200
    put_response = 204
    delete_response = 204
    response_data = json.dumps({"roles": []})

    def _response_side_effect(self, action, *args, **kwargs):
        response = mock.MagicMock()
        if action == "GET":
            response.status = self.get_response
            response.data = self.response_data
        if action == "PUT":
            response.status = self.put_response
        if action == "DELETE":
            response.status = self.delete_response
        return response

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_get_roles(self, http, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        http.request.side_effect = self._response_side_effect

        self.assertEqual({'admin_role_id': None, 'rbac_role_id': None},
                         self.rbac_utils.get_roles(caller))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_get_roles_member(self, http, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        self.response_data = json.dumps({'roles': [{'name': '_member_',
                                         'id': '_member_id'}]})
        http.request.side_effect = self._response_side_effect

        config.rbac.rbac_test_role = '_member_'

        self.assertEqual({'admin_role_id': None,
                          'rbac_role_id': '_member_id'},
                         self.rbac_utils.get_roles(caller))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_get_roles_admin(self, http, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        self.response_data = json.dumps({'roles': [{'name': 'admin',
                                         'id': 'admin_id'}]})

        http.request.side_effect = self._response_side_effect

        config.rbac.rbac_test_role = 'admin'

        self.assertEqual({'admin_role_id': 'admin_id',
                          'rbac_role_id': 'admin_id'},
                         self.rbac_utils.get_roles(caller))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_get_roles_admin_not_role(self, http, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        self.response_data = json.dumps(
            {'roles': [{'name': 'admin', 'id': 'admin_id'}]}
        )
        http.request.side_effect = self._response_side_effect

        self.assertEqual({'admin_role_id': 'admin_id', 'rbac_role_id': None},
                         self.rbac_utils.get_roles(caller))

    def test_RBAC_utils_get_existing_roles(self):
        self.rbac_utils.dictionary = {'admin_role_id': None,
                                      'rbac_role_id': None}

        self.assertEqual({'admin_role_id': None, 'rbac_role_id': None},
                         self.rbac_utils.get_roles(None))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_get_roles_response_404(self, http, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        http.request.side_effect = self._response_side_effect
        self.get_response = 404

        self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                          self.rbac_utils.get_roles, caller)
        self.get_response = 200

    def test_RBAC_utils_switch_roles_none(self):
        self.assertIsNone(self.rbac_utils.switch_role(None))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.RbacUtils.get_roles')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_switch_roles_member(self, http,
                                            get_roles, config):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}

        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"

        http.request.side_effect = self._response_side_effect

        self.assertIsNone(self.rbac_utils.switch_role(self, "_member_"))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.RbacUtils.get_roles')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_switch_roles_false(self, http,
                                           get_roles, config):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}

        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"

        http.request.side_effect = self._response_side_effect

        self.assertIsNone(self.rbac_utils.switch_role(self, False))

    @mock.patch('patrole_tempest_plugin.rbac_utils.CONF')
    @mock.patch('patrole_tempest_plugin.rbac_utils.RbacUtils.get_roles')
    @mock.patch('patrole_tempest_plugin.rbac_utils.http')
    def test_RBAC_utils_switch_roles_get_roles_fails(self, http,
                                                     get_roles, config):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}

        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"

        self.get_response = 404

        self.assertRaises(rbac_exceptions.RbacResourceSetupFailed,
                          self.rbac_utils.switch_role, self, False)

        self.get_response = 200

    @mock.patch('patrole_tempest_plugin.rbac_utils.RbacUtils.get_roles')
    def test_RBAC_utils_switch_roles_exception(self, get_roles):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}
        self.assertRaises(AttributeError, self.rbac_utils.switch_role,
                          self, "admin")
