#    Copyright 2017 AT&T Corporation.
#    All Rights Reserved.
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

from tempest.common import identity
from tempest.common import tempest_fixtures as fixtures
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class QuotaClassesRbacTest(rbac_base.BaseV2ComputeRbacTest):

    credentials = ['primary', 'admin']

    def setUp(self):
        # All test cases in this class need to externally lock on doing
        # anything with default quota values.
        self.useFixture(fixtures.LockFixture('compute_quotas'))
        super(QuotaClassesRbacTest, self).setUp()

    @classmethod
    def skip_checks(cls):
        super(QuotaClassesRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-quota-class-sets', 'compute'):
            msg = "%s skipped as os-quota-class-sets extension not enabled."\
                  % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(QuotaClassesRbacTest, cls).setup_clients()
        cls.quota_classes_client = cls.os_primary.quota_classes_client
        cls.identity_projects_client = cls.os_primary.projects_client

    @classmethod
    def resource_setup(cls):
        super(QuotaClassesRbacTest, cls).resource_setup()
        # Create a project with its own quota.
        project_name = data_utils.rand_name(cls.__name__ + '-project')
        project_desc = project_name + '-desc'
        project = identity.identity_utils(cls.os_admin).create_project(
            name=project_name, description=project_desc)
        cls.project_id = project['id']
        cls.addClassResourceCleanup(
            identity.identity_utils(cls.os_admin).delete_project,
            cls.project_id)

    @decorators.idempotent_id('c10198ed-9df2-440e-a49b-367dadc6de94')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-quota-class-sets:show"])
    def test_show_quota_class_set(self):
        with self.override_role():
            self.quota_classes_client.show_quota_class_set('default')

    @decorators.idempotent_id('81889e69-efd2-4e96-bb4c-ee3b646b9755')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-quota-class-sets:update"])
    def test_update_quota_class_set(self):
        # Update the pre-existing quotas for the project_id.
        quota_class_set = self.quota_classes_client.show_quota_class_set(
            self.project_id)['quota_class_set']
        quota_class_set.pop('id')
        for quota, default in quota_class_set.items():
            quota_class_set[quota] = default + 100

        with self.override_role():
            self.quota_classes_client.update_quota_class_set(
                self.project_id, **quota_class_set)
