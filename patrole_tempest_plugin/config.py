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

from oslo_config import cfg


patrole_group = cfg.OptGroup(name='patrole', title='Patrole Testing Options')


PatroleGroup = [
    cfg.StrOpt('rbac_test_role',
               default='admin',
               deprecated_group='rbac',
               help="""The current RBAC role against which to run Patrole
tests."""),
    cfg.BoolOpt('enable_rbac',
                default=True,
                deprecated_group='rbac',
                help="Enables RBAC tests."),
    cfg.BoolOpt('strict_policy_check',
                default=False,
                deprecated_group='rbac',
                help="""If true, throws RbacParsingException for policies which
don't exist or are not included in the service's policy file. If false, throws
skipException."""),
    # TODO(rb560u): There needs to be support for reading these JSON files from
    # other hosts. It may be possible to leverage the v3 identity policy API.
    cfg.ListOpt('custom_policy_files',
                default=['/etc/%s/policy.json'],
                deprecated_group='rbac',
                help="""List of the paths to search for policy files. Each
policy path assumes that the service name is included in the path once. Also
assumes Patrole is on the same host as the policy files. The paths should be
ordered by precedence, with high-priority paths before low-priority paths. The
first path that is found to contain the service's policy file will be used.
"""),
    cfg.StrOpt('cinder_policy_file',
               default='/etc/cinder/policy.json',
               help="""Location of the Cinder policy file. Assumed to be on
the same host as Patrole.""",
               deprecated_group='rbac',
               deprecated_for_removal=True,
               deprecated_reason="It is better to use `custom_policy_files` "
                                 "which supports any OpenStack service."),
    cfg.StrOpt('glance_policy_file',
               default='/etc/glance/policy.json',
               help="""Location of the Glance policy file. Assumed to be on
the same host as Patrole.""",
               deprecated_group='rbac',
               deprecated_for_removal=True,
               deprecated_reason="It is better to use `custom_policy_files` "
                                 "which supports any OpenStack service."),
    cfg.StrOpt('keystone_policy_file',
               default='/etc/keystone/policy.json',
               help="""Location of the custom Keystone policy file. Assumed to
be on the same host as Patrole.""",
               deprecated_group='rbac',
               deprecated_for_removal=True,
               deprecated_reason="It is better to use `custom_policy_files` "
                                 "which supports any OpenStack service."),
    cfg.StrOpt('neutron_policy_file',
               default='/etc/neutron/policy.json',
               help="""Location of the Neutron policy file. Assumed to be on
the same host as Patrole.""",
               deprecated_group='rbac',
               deprecated_for_removal=True,
               deprecated_reason="It is better to use `custom_policy_files` "
                                 "which supports any OpenStack service."),
    cfg.StrOpt('nova_policy_file',
               default='/etc/nova/policy.json',
               help="""Location of the custom Nova policy file. Assumed to be
on the same host as Patrole.""",
               deprecated_group='rbac',
               deprecated_for_removal=True,
               deprecated_reason="It is better to use `custom_policy_files` "
                                 "which supports any OpenStack service."),
    cfg.BoolOpt('test_custom_requirements',
                default=False,
                deprecated_group='rbac',
                help="""
This option determines whether Patrole should run against a
`custom_requirements_file` which defines RBAC requirements. The
purpose of setting this flag to True is to verify that RBAC policy
is in accordance to requirements. The idea is that the
`custom_requirements_file` perfectly defines what the RBAC requirements are.

Here are the possible outcomes when running the Patrole tests against
a `custom_requirements_file`:

YAML definition: allowed
test run: allowed
test result: pass

YAML definition: allowed
test run: not allowed
test result: fail (under-permission)

YAML definition: not allowed
test run: allowed
test result: fail (over-permission)
"""),
    cfg.StrOpt('custom_requirements_file',
               deprecated_group='rbac',
               help="""
File path of the yaml file that defines your RBAC requirements. This
file must be located on the same host that Patrole runs on. The yaml
file should be written as follows:

```
<service>:
  <api_action>:
    - <allowed_role>
    - <allowed_role>
    - <allowed_role>
  <api_action>:
    - <allowed_role>
    - <allowed_role>
<service>
  <api_action>:
    - <allowed_role>
```
Where:
service = the service that is being tested (cinder, nova, etc)
api_action = the policy action that is being tested. Examples:
             - volume:create
             - os_compute_api:servers:start
             - add_image
allowed_role = the Keystone role that is allowed to perform the API
""")
]


rbac_group = cfg.OptGroup(name='rbac',
                          title='RBAC testing options',
                          help="This group is deprecated and will be removed "
                               "in the next release. Use the [patrole] group "
                               "instead.")
