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

import contextlib
import sys
import time

from oslo_log import log as logging
from oslo_utils import excutils

from tempest import config
from tempest.lib import exceptions as lib_exc

from patrole_tempest_plugin import rbac_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class _ValidateListContext(object):
    """Context class responsible for validation of the list functions.

    This class is used in ``override_role_and_validate_list`` function and
    the result of a list function must be assigned to the ``ctx.resources``
    variable.

    Example::

        with self.override_role_and_validate_list(...) as ctx:
            ctx.resources = list_function()

    """
    def __init__(self, admin_resources=None, admin_resource_id=None):
        """Constructor for ``ValidateListContext``.

        Either ``admin_resources`` or ``admin_resource_id`` should be used,
            not both.

        :param list admin_resources: The list of resources received before
            calling the ``override_role_and_validate_list`` function. To
            validate will be used the ``_validate_len`` function.
        :param UUID admin_resource_id: An ID of a resource created before
            calling the ``override_role_and_validate_list`` function. To
            validate will be used the ``_validate_resource`` function.
        :raises RbacValidateListException: if both ``admin_resources`` and
            ``admin_resource_id`` are set or unset.
        """
        self.resources = None
        if admin_resources is not None and not admin_resource_id:
            self._admin_len = len(admin_resources)
            if not self._admin_len:
                raise rbac_exceptions.RbacValidateListException(
                    reason="the list of admin resources cannot be empty")
            self._validate_func = self._validate_len
        elif admin_resource_id and admin_resources is None:
            self._admin_resource_id = admin_resource_id
            self._validate_func = self._validate_resource
        else:
            raise rbac_exceptions.RbacValidateListException(
                reason="admin_resources and admin_resource_id are mutually "
                       "exclusive")

    def _validate_len(self):
        """Validates that the number of resources is less than admin resources.
        """
        if not len(self.resources):
            raise rbac_exceptions.RbacEmptyResponseBody()
        elif self._admin_len > len(self.resources):
            raise rbac_exceptions.RbacPartialResponseBody(body=self.resources)

    def _validate_resource(self):
        """Validates that the admin resource is present in the resources.
        """
        for resource in self.resources:
            if resource['id'] == self._admin_resource_id:
                return
        raise rbac_exceptions.RbacPartialResponseBody(body=self.resources)

    def _validate(self):
        """Calls the proper validation function.

        :raises RbacValidateListException: if the ``ctx.resources`` variable is
            not assigned.
        """
        if self.resources is None:
            raise rbac_exceptions.RbacValidateListException(
                reason="ctx.resources is not assigned")
        self._validate_func()


class RbacUtilsMixin(object):
    """Utility mixin responsible for switching ``os_primary`` role.

    Should be used as a mixin class alongside an instance of
    :py:class:`tempest.test.BaseTestCase` to perform Patrole class setup for a
    base RBAC class. Child classes should not use this mixin.

    Example::

        class BaseRbacTest(rbac_utils.RbacUtilsMixin, base.BaseV2ComputeTest):

            @classmethod
            def setup_clients(cls):
                super(BaseRbacTest, cls).setup_clients()

                cls.hosts_client = cls.os_primary.hosts_client
                ...

    This class is responsible for overriding the value of the primary Tempest
    credential's role (i.e. ``os_primary`` role). By doing so, it is possible
    to seamlessly swap between admin credentials, needed for setup and clean
    up, and primary credentials, needed to perform the API call which does
    policy enforcement. The primary credentials always cycle between roles
    defined by ``CONF.identity.admin_role`` and
    ``CONF.patrole.rbac_test_roles``.
    """
    credentials = ['primary', 'admin']

    def __init__(self, *args, **kwargs):
        super(RbacUtilsMixin, self).__init__(*args, **kwargs)

        # Shows if override_role was called.
        self.__override_role_called = False
        # Shows if exception raised during override_role.
        self.__override_role_caught_exc = False

    _admin_role_id = None
    _rbac_role_ids = None
    _project_id = None
    _user_id = None
    _role_map = None
    _role_inferences_mapping = None
    _orig_roles = []

    admin_roles_client = None

    @classmethod
    def restore_roles(cls):
        if cls._orig_roles:
            LOG.info("Restoring original roles %s", cls._orig_roles)
            roles_already_present = cls._list_and_clear_user_roles_on_project(
                cls._orig_roles)

            if not roles_already_present:
                cls._create_user_role_on_project(cls._orig_roles)

    @classmethod
    def setup_clients(cls):
        if CONF.identity_feature_enabled.api_v3:
            admin_roles_client = cls.os_admin.roles_v3_client
        else:
            raise lib_exc.InvalidConfiguration(
                "Patrole role overriding only supports v3 identity API.")

        cls.admin_roles_client = admin_roles_client

        cls._project_id = cls.os_primary.credentials.tenant_id
        cls._user_id = cls.os_primary.credentials.user_id
        cls._role_inferences_mapping = cls._prepare_role_inferences_mapping()

        cls._init_roles()

        # Store the user's original roles and rollback after testing.
        roles = cls.admin_roles_client.list_user_roles_on_project(
            cls._project_id, cls._user_id)['roles']
        cls._orig_roles = [role['id'] for role in roles]
        cls.addClassResourceCleanup(cls.restore_roles)

        # Change default role to admin
        cls._override_role(False)

        super(RbacUtilsMixin, cls).setup_clients()

    @classmethod
    def _prepare_role_inferences_mapping(cls):
        """Preparing roles mapping to support role inferences

        Making query to `list-all-role-inference-rules`_ keystone API
        returns all inference rules, which makes it possible to prepare
        roles mapping.

        It walks recursively through the raw data::

            {"role_inferences": [
                {
                  "implies": [{"id": "3", "name": "reader"}],
                  "prior_role": {"id": "2", "name": "member"}
                },
                {
                  "implies": [{"id": "2", "name": "member"}],
                  "prior_role": {"id": "1", "name": "admin"}
                }
              ]
            }

        and converts it to the mapping::

            {
              "2": ["3"],      # "member": ["reader"],
              "1": ["2", "3"]  # "admin": ["member", "reader"]
            }

        .. _list-all-role-inference-rules: https://docs.openstack.org/api-ref/identity/v3/#list-all-role-inference-rules
        """  # noqa: E501
        def process_roles(role_id, data):
            roles = data.get(role_id, set())
            for rid in roles.copy():
                roles.update(process_roles(rid, data))

            return roles

        def convert_data(data):
            res = {}
            for rule in data:
                prior_role = rule['prior_role']['id']
                implies = {r['id'] for r in rule['implies']}
                res[prior_role] = implies
            return res

        raw_data = cls.admin_roles_client.list_all_role_inference_rules()
        data = convert_data(raw_data['role_inferences'])
        res = {}
        for role_id in data:
            res[role_id] = process_roles(role_id, data)
        return res

    def get_all_needed_roles(self, roles):
        """Extending given roles with roles from mapping

        Examples::
            ["admin"] >> ["admin", "member", "reader"]
            ["member"] >> ["member", "reader"]
            ["reader"] >> ["reader"]
            ["custom_role"] >> ["custom_role"]

        :param roles: list of roles
        :return: extended list of roles
        """
        res = set(r for r in roles)
        for role in res.copy():
            role_id = self.__class__._role_map.get(role)
            implied_roles = self.__class__._role_inferences_mapping.get(
                role_id, set())
            role_names = {self.__class__._role_map[rid]
                          for rid in implied_roles}
            res.update(role_names)
        LOG.debug('All needed roles: %s; Base roles: %s', res, roles)
        return list(res)

    @contextlib.contextmanager
    def override_role(self):
        """Override the role used by ``os_primary`` Tempest credentials.

        Temporarily change the role used by ``os_primary`` credentials to:

        * ``[patrole] rbac_test_roles`` before test execution
        * ``[identity] admin_role`` after test execution

        Automatically switches to admin role after test execution.

        :returns: None

        .. warning::

            This function can alter user roles for pre-provisioned credentials.
            Work is underway to safely clean up after this function.

        Example::

            @rbac_rule_validation.action(service='test',
                                         rules=['a:test:rule'])
            def test_foo(self):
                # Allocate test-level resources here.
                with self.override_role():
                    # The role for `os_primary` has now been overridden. Within
                    # this block, call the API endpoint that enforces the
                    # expected policy specified by "rule" in the decorator.
                    self.foo_service.bar_api_call()
                # The role is switched back to admin automatically. Note that
                # if the API call above threw an exception, any code below this
                # point in the test is not executed.
        """
        self._set_override_role_called()
        self._override_role(True)
        try:
            # Execute the test.
            yield
        finally:
            # Check whether an exception was raised. If so, remember that
            # for future validation.
            exc = sys.exc_info()[0]
            if exc is not None:
                self._set_override_role_caught_exc()
            # This code block is always executed, no matter the result of the
            # test. Automatically switch back to the admin role for test clean
            # up.
            self._override_role(False)

    @classmethod
    def _override_role(cls, toggle_rbac_role=False):
        """Private helper for overriding ``os_primary`` Tempest credentials.

        :param toggle_rbac_role: Boolean value that controls the role that
            overrides default role of ``os_primary`` credentials.
            * If True: role is set to ``[patrole] rbac_test_role``
            * If False: role is set to ``[identity] admin_role``
        """
        LOG.debug('Overriding role to: %s.', toggle_rbac_role)
        roles_already_present = False

        try:
            target_roles = (cls._rbac_role_ids
                            if toggle_rbac_role else [cls._admin_role_id])
            roles_already_present = cls._list_and_clear_user_roles_on_project(
                target_roles)

            # Do not override roles if `target_role` already exists.
            if not roles_already_present:
                cls._create_user_role_on_project(target_roles)
        except Exception as exp:
            with excutils.save_and_reraise_exception():
                LOG.exception(exp)
        finally:
            auth_providers = cls.get_auth_providers()
            for provider in auth_providers:
                provider.clear_auth()
            # Fernet tokens are not subsecond aware so sleep to ensure we are
            # passing the second boundary before attempting to authenticate.
            # Only sleep if a token revocation occurred as a result of role
            # overriding. This will optimize test runtime in the case where
            # ``[identity] admin_role`` == ``[patrole] rbac_test_roles``.
            if not roles_already_present:
                time.sleep(1)

            for provider in auth_providers:
                provider.set_auth()

    @classmethod
    def _init_roles(cls):
        available_roles = cls.admin_roles_client.list_roles()['roles']
        cls._role_map = {r['name']: r['id'] for r in available_roles}
        LOG.debug('Available roles: %s', cls._role_map.keys())

        rbac_role_ids = []
        roles = CONF.patrole.rbac_test_roles
        # TODO(vegasq) drop once CONF.patrole.rbac_test_role is removed
        if CONF.patrole.rbac_test_role:
            if not roles:
                roles.append(CONF.patrole.rbac_test_role)

        for role_name in roles:
            rbac_role_ids.append(cls._role_map.get(role_name))

        admin_role_id = cls._role_map.get(CONF.identity.admin_role)

        if not all([admin_role_id, all(rbac_role_ids)]):
            missing_roles = []
            msg = ("Could not find `[patrole] rbac_test_roles` or "
                   "`[identity] admin_role`, both of which are required for "
                   "RBAC testing.")
            if not admin_role_id:
                missing_roles.append(CONF.identity.admin_role)
            if not all(rbac_role_ids):
                missing_roles += [role_name for role_name in roles
                                  if role_name not in cls._role_map]

            msg += " Following roles were not found: %s." % (
                ", ".join(missing_roles))
            msg += " Available roles: %s." % ", ".join(cls._role_map)
            raise rbac_exceptions.RbacResourceSetupFailed(msg)

        cls._admin_role_id = admin_role_id
        cls._rbac_role_ids = rbac_role_ids
        # Adding backward mapping
        cls._role_map.update({v: k for k, v in cls._role_map.items()})

    @classmethod
    def _create_user_role_on_project(cls, role_ids):
        for role_id in role_ids:
            cls.admin_roles_client.create_user_role_on_project(
                cls._project_id, cls._user_id, role_id)

    @classmethod
    def _list_and_clear_user_roles_on_project(cls, role_ids):
        roles = cls.admin_roles_client.list_user_roles_on_project(
            cls._project_id, cls._user_id)['roles']
        all_role_ids = [role['id'] for role in roles]

        # NOTE(felipemonteiro): We do not use ``role_id in all_role_ids`` here
        # to avoid over-permission errors: if the current list of roles on the
        # project includes "admin" and "Member", and we are switching to the
        # "Member" role, then we must delete the "admin" role. Thus, we only
        # return early if the user's roles on the project are an exact match.
        if set(role_ids) == set(all_role_ids):
            return True

        for role in roles:
            cls.admin_roles_client.delete_role_from_user_on_project(
                cls._project_id, cls._user_id, role['id'])

        return False

    @contextlib.contextmanager
    def override_role_and_validate_list(self,
                                        admin_resources=None,
                                        admin_resource_id=None):
        """Call ``override_role`` and validate RBAC for a list API action.

        List actions usually do soft authorization: partial or empty response
        bodies are returned instead of exceptions. This helper validates
        that unauthorized roles only return a subset of the available
        resources.
        Should only be used for validating list API actions.

        :param test_obj: Instance of ``tempest.test.BaseTestCase``.
        :param list admin_resources: The list of resources received before
            calling the ``override_role_and_validate_list`` function.
        :param UUID admin_resource_id: An ID of a resource created before
            calling the ``override_role_and_validate_list`` function.
        :return: py:class:`_ValidateListContext` object.

        Example::

            # the resource created by admin
            admin_resource_id = (
                self.ntp_client.create_dscp_marking_rule()
                ["dscp_marking_rule"]["id'])
            with self.override_role_and_validate_list(
                    admin_resource_id=admin_resource_id) as ctx:
                # the list of resources available for member role
                ctx.resources = self.ntp_client.list_dscp_marking_rules(
                    policy_id=self.policy_id)["dscp_marking_rules"]
        """
        ctx = _ValidateListContext(admin_resources, admin_resource_id)
        with self.override_role():
            yield ctx
            ctx._validate()

    @classmethod
    def get_auth_providers(cls):
        """Returns list of auth_providers used within test.

        Tests may redefine this method to include their own or third party
        client auth_providers.
        """
        return [cls.os_primary.auth_provider]

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

    :returns: True if ``rbac_test_roles`` contain the admin role.
    """
    roles = CONF.patrole.rbac_test_roles
    # TODO(vegasq) drop once CONF.patrole.rbac_test_role is removed
    if CONF.patrole.rbac_test_role:
        roles.append(CONF.patrole.rbac_test_role)
        roles = list(set(roles))

    # TODO(felipemonteiro): Make this more robust via a context is admin
    # lookup.
    return CONF.identity.admin_role in roles
