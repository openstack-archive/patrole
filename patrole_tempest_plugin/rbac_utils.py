# Copyright 2017 AT&T Corp
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
import logging
import six
import time
import urllib3

from tempest import config

from patrole_tempest_plugin import rbac_exceptions as rbac_exc

LOG = logging.getLogger(__name__)
CONF = config.CONF
http = urllib3.PoolManager()


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,
                                                                 **kwargs)
        return cls._instances[cls]


@six.add_metaclass(Singleton)
class RbacUtils(object):
    def __init__(self):
        RbacUtils.dictionary = {}

    @staticmethod
    def get_roles(caller):
        admin_role_id = None
        rbac_role_id = None

        if bool(RbacUtils.dictionary) is False:
            admin_token = caller.admin_client.token
            headers = {'X-Auth-Token': admin_token,
                       "Content-Type": "application/json"}
            url_to_get_role = CONF.identity.uri_v3 + '/roles/'
            response = http.request('GET', url_to_get_role, headers=headers)
            if response.status != 200:
                raise rbac_exc.RbacResourceSetupFailed('Unable to'
                                                       ' retrieve roles')
            data = response.data
            roles = json.loads(data)
            for item in roles['roles']:
                if item['name'] == CONF.rbac.rbac_test_role:
                    rbac_role_id = item['id']
                if item['name'] == 'admin':
                    admin_role_id = item['id']

            RbacUtils.dictionary.update({'admin_role_id': admin_role_id,
                                         'rbac_role_id': rbac_role_id})

        return RbacUtils.dictionary

    @staticmethod
    def delete_all_roles(self, base_url, headers):
        # Find the current role
        response = http.request('GET', base_url, headers=headers)
        if response.status != 200:
            raise rbac_exc.RbacResourceSetupFailed('Unable to retrieve'
                                                   ' user role')
        data = response.data
        roles = json.loads(data)
        for item in roles['roles']:
            url = base_url + item['id']
            response = http.request('DELETE', url, headers=headers)
            self.assertEqual(204, response.status)

    @staticmethod
    def switch_role(self, switchToRbacRole=None):
        LOG.debug('Switching role to: %s', switchToRbacRole)
        if switchToRbacRole is None:
            return

        roles = rbac_utils.get_roles(self)
        rbac_role_id = roles.get('rbac_role_id')
        admin_role_id = roles.get('admin_role_id')

        try:
            user_id = self.auth_provider.credentials.user_id
            project_id = self.auth_provider.credentials.tenant_id
            admin_token = self.admin_client.token

            headers = {'X-Auth-Token': admin_token,
                       "Content-Type": "application/json"}
            base_url = (CONF.identity.uri_v3 + '/projects/' + project_id +
                        '/users/' + user_id + '/roles/')

            rbac_utils.delete_all_roles(self, base_url, headers)

            if switchToRbacRole:
                url = base_url + rbac_role_id
                response = http.request('PUT', url, headers=headers)
                self.assertEqual(204, response.status)
            else:
                url = base_url + admin_role_id
                response = http.request('PUT', url, headers=headers)
                self.assertEqual(204, response.status)

        except Exception as exp:
            LOG.error(exp)
            raise
        finally:
                self.auth_provider.clear_auth()
                # Sleep to avoid 401 errors caused by rounding
                # In timing of fernet token creation
                time.sleep(1)
                self.auth_provider.set_auth()

rbac_utils = RbacUtils()
