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

import typing as ty
import warnings

from keystoneauth1.identity.v3 import base
from keystoneauth1 import loading
from keystoneauth1 import plugin

__all__ = ('MultiFactor',)


class MultiFactor(base.Auth):
    """A plugin for authenticating with multiple auth methods.

    :param string auth_url: Identity service endpoint for authentication.
    :param string auth_methods: names of the methods to authenticate with.
    :param string trust_id: Trust ID for trust scoping.
    :param string system_scope: System information to scope to.
    :param string domain_id: Domain ID for domain scoping.
    :param string domain_name: Domain name for domain scoping.
    :param string project_id: Project ID for project scoping.
    :param string project_name: Project name for project scoping.
    :param string project_domain_id: Project's domain ID for project.
    :param string project_domain_name: Project's domain name for project.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True

    Also accepts various keyword args based on which methods are specified.
    """

    def __init__(
        self,
        auth_url: str,
        auth_methods: list[str],
        *,
        unscoped: bool = False,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
        **kwargs: ty.Any,
    ):
        method_instances: list[base.AuthMethod] = []
        method_keys: set[str] = set()
        for method in auth_methods:
            # Using the loaders we pull the related auth method class
            loader: loading.BaseLoader[plugin.BaseAuthPlugin] = (
                loading.get_plugin_loader(method)
            )
            plugin_class = loader.plugin_class

            if issubclass(plugin_class, base.AuthConstructor):  # legacy path
                warnings.warn(
                    f"Support for {base.AuthConstructor.__qualname__} is "
                    f"deprecated and will be removed in a future release. "
                    f"Plugins should subclass for {base.Auth.__qualname__}.",
                    category=DeprecationWarning,
                )
                method_class = plugin_class._auth_method_class
                method_parameters = method_class._method_parameters or []
            elif issubclass(plugin_class, base.Auth) and isinstance(
                plugin_class, base.SupportsMultiFactor
            ):
                method_class = plugin_class._auth_method_class
                method_parameters = list(method_class.__annotations__)
            else:
                raise TypeError(
                    'The multifactor auth method can only be used with v3 '
                    'auth plugins that implement the SupportsMultiFactor '
                    'protocol'
                )

            # We build some new kwargs for the method from required parameters
            method_kwargs = {}
            for key in method_parameters:
                method_kwargs[key] = kwargs.get(key, None)
                # we also add them to method_keys to pop later from global
                # kwargs rather than here as other methods may need them too
                method_keys.add(key)

            # We initialize the method class using just required kwargs
            method_instances.append(method_class(**method_kwargs))

        # We now pop all the keys used for methods as otherwise they get passed
        # to the super class and throw errors
        for key in method_keys:
            kwargs.pop(key, None)

        # This should now be empty
        assert not kwargs  # nosec B101

        super().__init__(
            auth_url=auth_url,
            auth_methods=method_instances,
            unscoped=unscoped,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
        )
