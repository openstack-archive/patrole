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

import datetime

from six.moves.urllib import parse as urllib

from tempest.common import utils
from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base

CONF = config.CONF

if CONF.policy_feature_enabled.changed_nova_policies_ussuri:
    _INSTANCE_USAGE_LIST = "os_compute_api:os-instance-usage-audit-log:list"
    _INSTANCE_USAGE_SHOW = "os_compute_api:os-instance-usage-audit-log:show"
else:
    _INSTANCE_USAGE_LIST = "os_compute_api:os-instance-usage-audit-log"
    _INSTANCE_USAGE_SHOW = "os_compute_api:os-instance-usage-audit-log"


class InstanceUsagesAuditLogRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(InstanceUsagesAuditLogRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-instance-usage-audit-log',
                                          'compute'):
            msg = "os-instance-usage-audit-log extension not enabled."
            raise cls.skipException(msg)

    @decorators.idempotent_id('c80246c0-5c13-4ab0-97ba-91551cd53dc1')
    @rbac_rule_validation.action(
        service="nova", rules=[_INSTANCE_USAGE_LIST])
    def test_list_instance_usage_audit_logs(self):
        with self.override_role():
            (self.instance_usages_audit_log_client
                .list_instance_usage_audit_logs())

    @decorators.idempotent_id('ded8bfbd-5d90-4a58-aee0-d31231bf3c9b')
    @rbac_rule_validation.action(
        service="nova", rules=[_INSTANCE_USAGE_SHOW])
    def test_show_instance_usage_audit_log(self):
        now = datetime.datetime.now()

        with self.override_role():
            (self.instance_usages_audit_log_client.
                show_instance_usage_audit_log(
                    urllib.quote(now.strftime("%Y-%m-%d %H:%M:%S"))))
