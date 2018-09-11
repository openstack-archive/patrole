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
               help="""The current RBAC role against which to run
Patrole tests."""),
    cfg.BoolOpt('enable_rbac',
                default=True,
                deprecated_for_removal=True,
                deprecated_reason="""This is a legacy option that was
meaningful when Patrole existed downstream as a suite of tests inside Tempest.
Installing the Patrole plugin necessarily means that RBAC tests should be run.
This option is paradoxical with the Tempest plugin architecture.
""",
                deprecated_since='R',
                help="Enables Patrole RBAC tests."),
    cfg.ListOpt('custom_policy_files',
                default=['/etc/%s/policy.json'],
                help="""List of the paths to search for policy files. Each
policy path assumes that the service name is included in the path once. Also
assumes Patrole is on the same host as the policy files. The paths should be
ordered by precedence, with high-priority paths before low-priority paths. All
the paths that are found to contain the service's policy file will be used and
all policy files will be merged. Allowed ``json`` or ``yaml`` formats.
"""),
    cfg.BoolOpt('test_custom_requirements',
                default=False,
                help="""
This option determines whether Patrole should run against a
``custom_requirements_file`` which defines RBAC requirements. The
purpose of setting this flag to ``True`` is to verify that RBAC policy
is in accordance to requirements. The idea is that the
``custom_requirements_file`` precisely defines what the RBAC requirements are.

Here are the possible outcomes when running the Patrole tests against
a ``custom_requirements_file``:

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
               help="""
File path of the YAML file that defines your RBAC requirements. This
file must be located on the same host that Patrole runs on. The YAML
file should be written as follows:

.. code-block:: yaml

    <service_foo>:
      <api_action_a>:
        - <allowed_role_1>
        - <allowed_role_2>
        - <allowed_role_3>
      <api_action_b>:
        - <allowed_role_2>
        - <allowed_role_4>
    <service_bar>:
      <api_action_c>:
        - <allowed_role_3>

Where:

service = the service that is being tested (Cinder, Nova, etc.).

api_action = the policy action that is being tested. Examples:

* volume:create
* os_compute_api:servers:start
* add_image

allowed_role = the ``oslo.policy`` role that is allowed to perform the API.
""")
]


patrole_log_group = cfg.OptGroup(
    name='patrole_log', title='Patrole Logging Options')


PatroleLogGroup = [
    cfg.BoolOpt('enable_reporting',
                default=False,
                help="Enables reporting on RBAC expected and actual test "
                     "results for each Patrole test"),
    cfg.StrOpt('report_log_name',
               default='patrole.log',
               help="Name of file where output from 'enable_reporting' is "
                    "logged. Note that this file is recreated on each "
                    "invocation of patrole"),
    cfg.StrOpt('report_log_path',
               default='.',
               help="Path (relative or absolute) where the output from "
                    "'enable_reporting' is logged. This is combined with"
                    "report_log_name to generate the full path."),
]


policy_feature_enabled = cfg.OptGroup(
    name='policy-feature-enabled',
    title='Feature Flags for New or Changed Policies')


PolicyFeatureEnabledGroup = [
    # TODO(felipemonteiro): The 6 feature flags below should be removed after
    # Pike is EOL.
    cfg.BoolOpt('create_port_fixed_ips_ip_address_policy',
                default=True,
                help="""Is the Neutron policy
"create_port:fixed_ips:ip_address" available in the cloud? This policy was
changed in a backwards-incompatible way."""),
    cfg.BoolOpt('update_port_fixed_ips_ip_address_policy',
                default=True,
                help="""Is the Neutron policy
"update_port:fixed_ips:ip_address" available in the cloud? This policy was
changed in a backwards-incompatible way."""),
    cfg.BoolOpt('limits_extension_used_limits_policy',
                default=True,
                help="""Is the Cinder policy
"limits_extension:used_limits" available in the cloud? This policy was
changed in a backwards-incompatible way."""),
    cfg.BoolOpt('volume_extension_volume_actions_attach_policy',
                default=True,
                help="""Is the Cinder policy
"volume_extension:volume_actions:attach" available in the cloud? This policy
was changed in a backwards-incompatible way."""),
    cfg.BoolOpt('volume_extension_volume_actions_reserve_policy',
                default=True,
                help="""Is the Cinder policy
"volume_extension:volume_actions:reserve" available in the cloud? This policy
was changed in a backwards-incompatible way."""),
    cfg.BoolOpt('volume_extension_volume_actions_unreserve_policy',
                default=True,
                help="""Is the Cinder policy
"volume_extension:volume_actions:unreserve" available in the cloud? This policy
was changed in a backwards-incompatible way."""),
    # *** Include feature flags for groups of policies below. ***
    # Best practice is to capture new policies, removed policies, renamed
    # policies in a group, per release.
    #
    # TODO(felipemonteiro): Remove these feature flags once Stein is EOL.
    cfg.BoolOpt('removed_nova_policies_stein',
                default=True,
                help="""Are the Nova API extension policies available in the
cloud (e.g. os_compute_api:os-extended-availability-zone)? These policies were
removed in Stein because Nova API extension concept was removed in Pike."""),
]


def list_opts():
    """Return a list of oslo.config options available.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users.
    """
    opt_list = [
        (patrole_group, PatroleGroup),
        (patrole_log_group, PatroleLogGroup),
        (policy_feature_enabled, PolicyFeatureEnabledGroup)

    ]

    return opt_list
