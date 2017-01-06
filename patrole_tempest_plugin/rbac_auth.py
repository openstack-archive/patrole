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

from oslo_log import log as logging
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_role_converter

LOG = logging.getLogger(__name__)


class RbacAuthority(object):
    def __init__(self, component=None, service=None):
        self.converter = rbac_role_converter.RbacPolicyConverter(service)
        self.roles_dict = self.converter.rules

    def get_permission(self, api, role):
        if self.roles_dict is None:
            raise exceptions.InvalidConfiguration("Roles dictionary is empty!")
        try:
            _api = self.roles_dict[api]
            if role in _api:
                LOG.debug("[API]: %s, [Role]: %s is allowed!", api, role)
                return True
            else:
                LOG.debug("[API]: %s, [Role]: %s  is NOT allowed!", api, role)
                return False
        except KeyError:
            raise KeyError("'%s' API is not defined in the policy.json"
                           % api)
        return False
