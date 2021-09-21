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

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF

if CONF.policy_feature_enabled.changed_cinder_policies_xena:
    _QUOTA_SET_SHOW = "volume_extension:quota_classes:get"
    _QUOTA_SET_UPDATE = "volume_extension:quota_classes:update"
else:
    _QUOTA_SET_SHOW = "volume_extension:quota_classes"
    _QUOTA_SET_UPDATE = "volume_extension:quota_classes"


class QuotaClassesV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(QuotaClassesV3RbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-quota-class-sets', 'volume'):
            msg = ("%s skipped as os-quota-class-sets not enabled."
                   % cls.__name__)
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(QuotaClassesV3RbacTest, cls).setup_clients()
        cls.quota_classes_client = cls.os_primary.quota_classes_client
        cls.quota_name = data_utils.rand_name(cls.__name__ + '-QuotaClass')

    @decorators.idempotent_id('1a060def-2b43-4534-97f5-5eadbbe8c726')
    @rbac_rule_validation.action(service="cinder",
                                 rules=[_QUOTA_SET_SHOW])
    def test_show_quota_class_set(self):
        with self.override_role():
            self.quota_classes_client.show_quota_class_set(
                self.quota_name)['quota_class_set']

    @decorators.idempotent_id('72159478-23a7-4c75-989f-6bac609eca62')
    @rbac_rule_validation.action(service="cinder",
                                 rules=[_QUOTA_SET_UPDATE])
    def test_update_quota_class_set(self):
        quota_class_set = self.quota_classes_client.show_quota_class_set(
            self.quota_name)['quota_class_set']
        quota_class_set.pop('id')

        with self.override_role():
            self.quota_classes_client.update_quota_class_set(self.quota_name,
                                                             **quota_class_set)
