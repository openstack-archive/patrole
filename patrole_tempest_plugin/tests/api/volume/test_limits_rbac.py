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

import testtools

from tempest import config
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base

CONF = config.CONF


class LimitsV3RbacTest(rbac_base.BaseVolumeRbacTest):
    _api_version = 3

    @testtools.skipUnless(
        CONF.policy_feature_enabled.limits_extension_used_limits_policy,
        '"limits_extension:used_limits" must be available in the cloud.')
    @decorators.idempotent_id('dab04510-5b86-4479-a633-6e496ff405af')
    @rbac_rule_validation.action(service="cinder",
                                 rule="limits_extension:used_limits")
    def test_show_limits(self):
        # It is enough to check whether any of the following keys below
        # are in the response body under ['limits']['absolute'], but no harm
        # in checking for them all.
        expected_keys = {
            'totalVolumesUsed',
            'totalGigabytesUsed',
            'totalSnapshotsUsed',
            'totalBackupsUsed',
            'totalBackupGigabytesUsed'
        }

        with self.rbac_utils.override_role(self):
            absolute_limits = self.volume_limits_client.show_limits()[
                'limits']['absolute']
        for key in expected_keys:
            if key not in absolute_limits:
                raise rbac_exceptions.RbacMalformedResponse(attribute=key)
