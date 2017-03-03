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

import logging

from tempest import config
from tempest.lib import exceptions

from patrole_tempest_plugin import rbac_auth
from patrole_tempest_plugin import rbac_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


def action(service, rule):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                tenant_id = args[0].auth_provider.credentials.tenant_id
                user_id = args[0].auth_provider.credentials.user_id
            except (IndexError, AttributeError) as e:
                msg = ("{0}: tenant_id/user_id not found in "
                       "cls.auth_provider.credentials".format(e))
                LOG.error(msg)
                raise rbac_exceptions.RbacResourceSetupFailed(msg)
            authority = rbac_auth.RbacAuthority(tenant_id, user_id, service)
            allowed = authority.get_permission(rule, CONF.rbac.rbac_test_role)

            try:
                func(*args)
            except exceptions.Forbidden as e:
                if allowed:
                    msg = ("Role %s was not allowed to perform %s." %
                           (CONF.rbac.rbac_test_role, rule))
                    LOG.error(msg)
                    raise exceptions.Forbidden(
                        "%s exception was: %s" %
                        (msg, e))
            except rbac_exceptions.RbacActionFailed as e:
                if allowed:
                    msg = ("Role %s was not allowed to perform %s." %
                           (CONF.rbac.rbac_test_role, rule))
                    LOG.error(msg)
                    raise exceptions.Forbidden(
                        "%s RbacActionFailed was: %s" %
                        (msg, e))
            else:
                if not allowed:
                    LOG.error("Role %s was allowed to perform %s" %
                              (CONF.rbac.rbac_test_role, rule))
                    raise rbac_exceptions.RbacOverPermission(
                        "OverPermission: Role %s was allowed to perform %s" %
                        (CONF.rbac.rbac_test_role, rule))
        return wrapper
    return decorator
