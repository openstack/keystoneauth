# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import importlib.metadata
from unittest import mock

import stevedore
from stevedore import extension

from keystoneauth1 import loading
from keystoneauth1.loading import base
from keystoneauth1.tests.unit.loading import utils


class EntryPointTests(utils.TestCase):
    """Simple test that will check that all entry points are loadable."""

    def test_all_entry_points_are_valid(self):
        errors = []

        def raise_exception_callback(manager, entrypoint, exc):
            error = f"Cannot load '{entrypoint}' entry_point: {exc}'"
            errors.append(error)

        stevedore.ExtensionManager(
            namespace=loading.PLUGIN_NAMESPACE,
            on_load_failure_callback=raise_exception_callback,
        )

        self.assertEqual([], errors)


class ConflictResolverTests(utils.TestCase):
    """Verify duplicate plugin names prefer the out-of-tree implementation."""

    def _make_extension(self, name, target, obj=None):
        entry_point = importlib.metadata.EntryPoint(
            name=name, value=target, group=loading.PLUGIN_NAMESPACE
        )
        return extension.Extension(name, entry_point, None, obj)

    def test_prefers_out_of_tree_plugin(self):
        in_tree = self._make_extension(
            'v3websso', 'keystoneauth1.loading._plugins.identity.v3:WebSSO'
        )
        out_of_tree = self._make_extension(
            'v3websso', 'some_package.plugins:WebSSO'
        )

        # regardless of ordering the out-of-tree extension should win
        self.assertIs(
            out_of_tree,
            base._prefer_out_of_tree_plugin(
                loading.PLUGIN_NAMESPACE, 'v3websso', [in_tree, out_of_tree]
            ),
        )
        self.assertIs(
            out_of_tree,
            base._prefer_out_of_tree_plugin(
                loading.PLUGIN_NAMESPACE, 'v3websso', [out_of_tree, in_tree]
            ),
        )

    def test_falls_back_to_last_when_all_in_tree(self):
        first = self._make_extension(
            'v3websso', 'keystoneauth1.loading._plugins.identity.v3:WebSSO'
        )
        second = self._make_extension(
            'v3websso', 'keystoneauth1.extras._websso:WebSSO'
        )

        self.assertIs(
            second,
            base._prefer_out_of_tree_plugin(
                loading.PLUGIN_NAMESPACE, 'v3websso', [first, second]
            ),
        )

    def test_available_loaders_prefers_out_of_tree_plugin(self):
        in_tree_loader = object()
        out_of_tree_loader = object()
        in_tree = self._make_extension(
            'v3websso',
            'keystoneauth1.loading._plugins.identity.v3:WebSSO',
            in_tree_loader,
        )
        out_of_tree = self._make_extension(
            'v3websso', 'some_package.plugins:WebSSO', out_of_tree_loader
        )

        for extensions in ([in_tree, out_of_tree], [out_of_tree, in_tree]):
            manager = extension.ExtensionManager.make_test_instance(
                extensions,
                namespace=loading.PLUGIN_NAMESPACE,
                conflict_resolver=base._prefer_out_of_tree_plugin,
            )
            with mock.patch.object(
                stevedore, 'EnabledExtensionManager', return_value=manager
            ):
                loaders = loading.get_available_plugin_loaders()

            self.assertIs(out_of_tree_loader, loaders['v3websso'])
