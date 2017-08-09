# Copyright 2013 IBM Corp.
# Copyright 2017 AT&T Corporation.
# All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import os
import re

import pep8


PYTHON_CLIENTS = ['cinder', 'glance', 'keystone', 'nova', 'swift', 'neutron',
                  'ironic', 'heat', 'sahara']

PYTHON_CLIENT_RE = re.compile('import (%s)client' % '|'.join(PYTHON_CLIENTS))
TEST_DEFINITION = re.compile(r'^\s*def test.*')
SETUP_TEARDOWN_CLASS_DEFINITION = re.compile(r'^\s+def (setUp|tearDown)Class')
SCENARIO_DECORATOR = re.compile(r'\s*@.*services\((.*)\)')
VI_HEADER_RE = re.compile(r"^#\s+vim?:.+")
RAND_NAME_HYPHEN_RE = re.compile(r".*rand_name\(.+[\-\_][\"\']\)")
MUTABLE_DEFAULT_ARGS = re.compile(r"^\s*def .+\((.+=\{\}|.+=\[\])")
TESTTOOLS_SKIP_DECORATOR = re.compile(r'\s*@testtools\.skip\((.*)\)')
CLASS = re.compile(r"^class .+")
RBAC_CLASS_NAME_RE = re.compile(r'class .+RbacTest')
RULE_VALIDATION_DECORATOR = re.compile(
    r'\s*@rbac_rule_validation.action\(.*')
IDEMPOTENT_ID_DECORATOR = re.compile(r'\s*@decorators\.idempotent_id\((.*)\)')

have_rbac_decorator = False


def import_no_clients_in_api_tests(physical_line, filename):
    """Check for client imports from patrole_tempest_plugin/tests/api

    T102: Cannot import OpenStack python clients
    """
    if "patrole_tempest_plugin/tests/api" in filename:
        res = PYTHON_CLIENT_RE.match(physical_line)
        if res:
            return (physical_line.find(res.group(1)),
                    ("T102: python clients import not allowed "
                     "in patrole_tempest_plugin/tests/api/* or "
                     "patrole_tempest_plugin/tests/scenario/* tests"))


def no_setup_teardown_class_for_tests(physical_line, filename):
    """Check that tests do not use setUpClass/tearDownClass

    T105: Tests cannot use setUpClass/tearDownClass
    """
    if pep8.noqa(physical_line):
        return

    if SETUP_TEARDOWN_CLASS_DEFINITION.match(physical_line):
        return (physical_line.find('def'),
                "T105: (setUp|tearDown)Class can not be used in tests")


def no_vi_headers(physical_line, line_number, lines):
    """Check for vi editor configuration in source files.

    By default vi modelines can only appear in the first or
    last 5 lines of a source file.

    T106
    """
    # NOTE(gilliard): line_number is 1-indexed
    if line_number <= 5 or line_number > len(lines) - 5:
        if VI_HEADER_RE.match(physical_line):
            return 0, "T106: Don't put vi configuration in source files"


def service_tags_not_in_module_path(physical_line, filename):
    """Check that a service tag isn't in the module path

    A service tag should only be added if the service name isn't already in
    the module path.

    T107
    """
    matches = SCENARIO_DECORATOR.match(physical_line)
    if matches:
        services = matches.group(1).split(',')
        for service in services:
            service_name = service.strip().strip("'")
            modulepath = os.path.split(filename)[0]
            if service_name in modulepath:
                return (physical_line.find(service_name),
                        "T107: service tag should not be in path")


def no_hyphen_at_end_of_rand_name(logical_line, filename):
    """Check no hyphen at the end of rand_name() argument

    T108
    """
    msg = "T108: hyphen should not be specified at the end of rand_name()"
    if RAND_NAME_HYPHEN_RE.match(logical_line):
        return 0, msg


def no_mutable_default_args(logical_line):
    """Check that mutable object isn't used as default argument

    N322: Method's default argument shouldn't be mutable
    """
    msg = "N322: Method's default argument shouldn't be mutable!"
    if MUTABLE_DEFAULT_ARGS.match(logical_line):
        yield (0, msg)


def no_testtools_skip_decorator(logical_line):
    """Check that methods do not have the testtools.skip decorator

    T109
    """
    if TESTTOOLS_SKIP_DECORATOR.match(logical_line):
        yield (0, "T109: Cannot use testtools.skip decorator; instead use "
               "decorators.skip_because from tempest.lib")


def use_rand_uuid_instead_of_uuid4(logical_line, filename):
    """Check that tests use data_utils.rand_uuid() instead of uuid.uuid4()

    T113
    """
    if 'uuid.uuid4()' not in logical_line:
        return

    msg = ("T113: Tests should use data_utils.rand_uuid()/rand_uuid_hex() "
           "instead of uuid.uuid4()/uuid.uuid4().hex")
    yield (0, msg)


def no_rbac_rule_validation_decorator(physical_line, filename):
    """Check that each test has the ``rbac_rule_validation.action`` decorator.

    Checks whether the test function has "@rbac_rule_validation.action"
    above it; otherwise checks that it has "@decorators.idempotent_id" above
    it and "@rbac_rule_validation.action" above that.

    Assumes that ``rbac_rule_validation.action`` decorator is either the first
    or second decorator above the test function; otherwise this check fails.

    P100
    """
    global have_rbac_decorator

    if ("patrole_tempest_plugin/tests/api" in filename or
            "patrole_tempest_plugin/tests/scenario" in filename):

        if RULE_VALIDATION_DECORATOR.match(physical_line):
            have_rbac_decorator = True
            return

        if TEST_DEFINITION.match(physical_line):
            if not have_rbac_decorator:
                return (0, "Must use rbac_rule_validation.action "
                           "decorator for API and scenario tests")

            have_rbac_decorator = False


def no_rbac_suffix_in_test_filename(filename):
    """Check that RBAC filenames end with "_rbac" suffix.

    P101
    """
    if "patrole_tempest_plugin/tests/api" in filename:

        if filename.endswith('rbac_base.py'):
            return

        if not filename.endswith('_rbac.py'):
            return 0, "RBAC test filenames must end in _rbac suffix"


def no_rbac_test_suffix_in_test_class_name(physical_line, filename):
    """Check that RBAC class names end with "RbacTest"

    P102
    """
    if "patrole_tempest_plugin/tests/api" in filename:

        if filename.endswith('rbac_base.py'):
            return

        if CLASS.match(physical_line):
            if not RBAC_CLASS_NAME_RE.match(physical_line):
                return 0, "RBAC test class names must end in 'RbacTest'"


def no_client_alias_in_test_cases(logical_line, filename):
    """Check that test cases don't use "self.client" to define a client.

    P103
    """
    if "patrole_tempest_plugin/tests/api" in filename:
        if "self.client" in logical_line or "cls.client" in logical_line:
            return 0, "Do not use 'self.client' as a service client alias"


def factory(register):
    register(import_no_clients_in_api_tests)
    register(no_setup_teardown_class_for_tests)
    register(no_vi_headers)
    register(no_hyphen_at_end_of_rand_name)
    register(no_mutable_default_args)
    register(no_testtools_skip_decorator)
    register(use_rand_uuid_instead_of_uuid4)
    register(service_tags_not_in_module_path)
    register(no_rbac_rule_validation_decorator)
    register(no_rbac_suffix_in_test_filename)
    register(no_rbac_test_suffix_in_test_class_name)
