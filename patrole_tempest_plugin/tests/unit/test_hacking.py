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

from tempest.tests import base

from patrole_tempest_plugin.hacking import checks


class RBACHackingTestCase(base.TestCase):

    def test_import_no_clients_in_api_tests(self):
        for client in checks.PYTHON_CLIENTS:
            import_string = "import " + client + "client"
            self.assertTrue(checks.import_no_clients_in_api_tests(
                import_string,
                "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
            self.assertFalse(checks.import_no_clients_in_api_tests(
                import_string,
                "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
            self.assertFalse(checks.import_no_clients_in_api_tests(
                import_string,
                "./patrole_tempest_plugin/tests/unit/fake_test.py"))
            self.assertFalse(checks.import_no_clients_in_api_tests(
                import_string,
                "./patrole_tempest_plugin/fake_test.py"))

    def test_no_setup_teardown_class_for_tests(self):
        self.assertTrue(checks.no_setup_teardown_class_for_tests(
            "  def setUpClass(cls):",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertIsNone(checks.no_setup_teardown_class_for_tests(
            "  def setUpClass(cls): # noqa",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertTrue(checks.no_setup_teardown_class_for_tests(
            "  def setUpClass(cls):",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertTrue(checks.no_setup_teardown_class_for_tests(
            "  def setUpClass(cls):",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertTrue(checks.no_setup_teardown_class_for_tests(
            "  def tearDownClass(cls):",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertIsNone(checks.no_setup_teardown_class_for_tests(
            "  def tearDownClass(cls): # noqa",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertTrue(checks.no_setup_teardown_class_for_tests(
            "  def tearDownClass(cls):",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertTrue(checks.no_setup_teardown_class_for_tests(
            "  def tearDownClass(cls):",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))

    def test_no_vi_headers(self):
        self.assertTrue(checks.no_vi_headers(
            "# vim: tabstop=4", 1, range(250)))
        self.assertTrue(checks.no_vi_headers(
            "# vim: tabstop=4", 249, range(250)))

    def test_service_tags_not_in_module_path(self):
        self.assertTrue(checks.service_tags_not_in_module_path(
            "@utils.services('volume')",
            "./patrole_tempest_plugin/tests/api/volume/fake_test_rbac.py"))
        self.assertFalse(checks.service_tags_not_in_module_path(
            "@utils.services('image')",
            "./patrole_tempest_plugin/tests/api/volume/fake_test_rbac.py"))

    def test_no_hyphen_at_end_of_rand_name(self):
        self.assertIsNone(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test')",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertIsNone(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test')",
            "./patrole_tempest_plugin/tests/api/compute/fake_test_rbac.py"))
        self.assertIsNone(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test')",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertIsNone(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test')",
            "./patrole_tempest_plugin/tests/unit/fake_test.py"))
        self.assertTrue(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test-')",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertTrue(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test-')",
            "./patrole_tempest_plugin/tests/api/compute/fake_test_rbac.py"))
        self.assertTrue(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test-')",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertTrue(checks.no_hyphen_at_end_of_rand_name(
            "data_utils.rand_name('test-')",
            "./patrole_tempest_plugin/tests/unit/fake_test.py"))

    def test_no_mutable_default_args(self):
        self.assertEqual(0, len(list(checks.no_mutable_default_args(
            "  def test_function(test_param_1, test_param_2"))))
        self.assertEqual(1, len(list(checks.no_mutable_default_args(
            "  def test_function(test_param_1, test_param_2={}"))))

    def test_no_testtools_skip_decorator(self):
        self.assertEqual(1, len(list(checks.no_testtools_skip_decorator(
            " @testtools.skip('Bug')"))))
        self.assertEqual(0, len(list(checks.no_testtools_skip_decorator(
            " @testtools.skipTest('reason')"))))
        self.assertEqual(0, len(list(checks.no_testtools_skip_decorator(
            " @testtools.skipUnless(reason, 'message')"))))
        self.assertEqual(0, len(list(checks.no_testtools_skip_decorator(
            " @testtools.skipIf(reason, 'message')"))))

    def test_use_rand_uuid_instead_of_uuid4(self):
        self.assertTrue(checks.use_rand_uuid_instead_of_uuid4(
            "new_uuid = uuid.uuid4()",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertTrue(checks.use_rand_uuid_instead_of_uuid4(
            "new_hex_uuid = uuid.uuid4().hex",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertIsNotNone(checks.use_rand_uuid_instead_of_uuid4(
            "new_uuid = data_utils.rand_uuid()",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertIsNotNone(checks.use_rand_uuid_instead_of_uuid4(
            "new_hex_uuid = data_utils.rand_uuid_hex()",
            "./patrole_tempest_plugin/tests/fake_test.py"))

    def _test_no_rbac_rule_validation_decorator(
            self, filename, with_other_decorators=True,
            with_rbac_decorator=True, expected_success=True):
        other_decorators = [
            "@decorators.idempotent_id(123)",
            "@decorators.attr(type=['slow'])",
            "@utils.requires_ext(extension='ext', service='svc')"
        ]

        if with_other_decorators:
            # Include multiple decorators to verify that this check works with
            # arbitrarily many decorators. These insert decorators above the
            # rbac_rule_validation decorator.
            for decorator in other_decorators:
                self.assertIsNone(checks.no_rbac_rule_validation_decorator(
                    " %s" % decorator, filename))
        if with_rbac_decorator:
            self.assertIsNone(checks.no_rbac_rule_validation_decorator(
                " @rbac_rule_validation.action('rule')",
                filename))
        if with_other_decorators:
            # Include multiple decorators to verify that this check works with
            # arbitrarily many decorators. These insert decorators between
            # the test and the @rbac_rule_validation decorator.
            for decorator in other_decorators:
                self.assertIsNone(checks.no_rbac_rule_validation_decorator(
                    " %s" % decorator, filename))
        final_result = checks.no_rbac_rule_validation_decorator(
            " def test_rbac_test",
            filename)
        if expected_success:
            self.assertIsNone(final_result)
        else:
            self.assertIsInstance(final_result, tuple)
            self.assertFalse(final_result[0])

    def test_no_rbac_rule_validation_decorator(self):
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py")
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py",
            False)
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py",
            with_other_decorators=True, with_rbac_decorator=False,
            expected_success=False)
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py",
            with_other_decorators=False, with_rbac_decorator=False,
            expected_success=False)

        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/scenario/fake_test.py")
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/scenario/fake_test.py",
            False)
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/scenario/fake_test.py",
            with_other_decorators=True, with_rbac_decorator=False,
            expected_success=False)
        self._test_no_rbac_rule_validation_decorator(
            "./patrole_tempest_plugin/tests/scenario/fake_test.py",
            with_other_decorators=False, with_rbac_decorator=False,
            expected_success=False)

    def test_no_rbac_suffix_in_test_filename(self):
        self.assertFalse(checks.no_rbac_suffix_in_test_filename(
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertFalse(checks.no_rbac_suffix_in_test_filename(
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertFalse(checks.no_rbac_suffix_in_test_filename(
            "./patrole_tempest_plugin/tests/unit/fake_test.py"))
        self.assertFalse(checks.no_rbac_suffix_in_test_filename(
            "./patrole_tempest_plugin/tests/api/fake_rbac_base.py"))
        self.assertFalse(checks.no_rbac_suffix_in_test_filename(
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertTrue(checks.no_rbac_suffix_in_test_filename(
            "./patrole_tempest_plugin/tests/api/fake_test.py"))

    def test_no_rbac_test_suffix_in_test_class_name(self):
        self.assertFalse(checks.no_rbac_test_suffix_in_test_class_name(
            "class FakeTest",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertFalse(checks.no_rbac_test_suffix_in_test_class_name(
            "class FakeTest",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertFalse(checks.no_rbac_test_suffix_in_test_class_name(
            "class FakeTest",
            "./patrole_tempest_plugin/tests/unit/fake_test.py"))
        self.assertFalse(checks.no_rbac_test_suffix_in_test_class_name(
            "class FakeTest",
            "./patrole_tempest_plugin/tests/api/fake_rbac_base.py"))
        self.assertFalse(checks.no_rbac_test_suffix_in_test_class_name(
            "class FakeRbacTest",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertTrue(checks.no_rbac_test_suffix_in_test_class_name(
            "class FakeTest",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))

    def test_no_client_alias_in_test_cases(self):
        self.assertFalse(checks.no_client_alias_in_test_cases(
            "  self.client",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertFalse(checks.no_client_alias_in_test_cases(
            "  cls.client",
            "./patrole_tempest_plugin/tests/fake_test.py"))
        self.assertFalse(checks.no_client_alias_in_test_cases(
            "  self.client",
            "./patrole_tempest_plugin/tests/unit/fake_test.py"))
        self.assertFalse(checks.no_client_alias_in_test_cases(
            "  cls.client",
            "./patrole_tempest_plugin/tests/unit/fake_test.py"))
        self.assertFalse(checks.no_client_alias_in_test_cases(
            "  self.client",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertFalse(checks.no_client_alias_in_test_cases(
            "  cls.client",
            "./patrole_tempest_plugin/tests/scenario/fake_test.py"))
        self.assertTrue(checks.no_client_alias_in_test_cases(
            "  self.client",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertTrue(checks.no_client_alias_in_test_cases(
            "  cls.client",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))

    def test_no_plugin_rbac_test_suffix_in_plugin_test_class_name(self):
        check = checks.no_plugin_rbac_test_suffix_in_plugin_test_class_name

        # Passing cases: these do not inherit from "PluginRbacTest" base class.
        self.assertFalse(check(
            "class FakeRbacTest",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertFalse(check(
            "class FakeRbacTest(base.BaseFakeRbacTest)",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))

        # Passing cases: these **do** end in correct test class suffix.
        self.assertFalse(check(
            "class FakePluginRbacTest",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertFalse(check(
            "class FakePluginRbacTest(base.BaseFakeRbacTest)",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))

        # Failing cases: these **do not** end in correct test class suffix.
        self.assertTrue(check(
            "class FakeRbacTest(BaseFakePluginRbacTest)",
            "./patrole_tempest_plugin/tests/api/fake_test_rbac.py"))
        self.assertTrue(check(
            "class FakeRbacTest(BaseFakeNetworkPluginRbacTest)",
            "./patrole_tempest_plugin/tests/api/network/fake_test_rbac.py"))
