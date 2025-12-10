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

import datetime
import typing as ty

import typing_extensions as ty_ext

from keystoneauth1 import _utils as utils

__all__ = ('DiscoveryList', 'V2Discovery', 'V3Discovery', 'VersionDiscovery')

_DEFAULT_DAYS_AGO = 30


class Link(ty.TypedDict):
    href: str
    rel: str
    type: ty_ext.NotRequired[str]


class MediaType(ty.TypedDict):
    base: str
    type: str


class DiscoveryBase(dict[str, ty.Any]):
    """The basic version discovery structure.

    All version discovery elements should have access to these values.

    :param string id: The version id for this version entry.
    :param string status: The status of this entry.
    :param DateTime updated: When the API was last updated.
    """

    def __init__(
        self,
        id: str,
        *,
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> None:
        super().__init__()

        self.id = id
        self.status = status or 'stable'
        self.updated = updated or utils.before_utcnow(days=_DEFAULT_DAYS_AGO)

    @property
    def id(self) -> str:
        result: str = self['id']
        return result

    @id.setter
    def id(self, value: str) -> None:
        self['id'] = value

    @property
    def status(self) -> str | None:
        return self.get('status')

    @status.setter
    def status(self, value: str | None) -> None:
        self['status'] = value

    @property
    def updated_str(self) -> str | None:
        return self.get('updated')

    @updated_str.setter
    def updated_str(self, value: str) -> None:
        self['updated'] = value

    @property
    def updated(self) -> datetime.datetime:
        assert self.updated_str is not None
        return utils.parse_isotime(self.updated_str)

    @updated.setter
    def updated(self, value: datetime.datetime) -> None:
        self.updated_str = value.isoformat()

    @property
    def links(self) -> list[Link]:
        result: list[Link] = self.setdefault('links', [])
        return result

    def add_link(
        self, href: str, rel: str = 'self', type: str | None = None
    ) -> Link:
        link: Link = {'href': href, 'rel': rel}
        if type:
            link['type'] = type
        self.links.append(link)
        return link

    @property
    def media_types(self) -> list[MediaType]:
        result: list[MediaType] = self.setdefault('media-types', [])
        return result

    def add_media_type(self, base: str, type: str) -> MediaType:
        mt: MediaType = {'base': base, 'type': type}
        self.media_types.append(mt)
        return mt


class VersionDiscovery(DiscoveryBase):
    """A Version element for non-keystone services without microversions.

    Provides some default values and helper methods for creating a microversion
    endpoint version structure. Clients should use this instead of creating
    their own structures.

    :param string href: The url that this entry should point to.
    :param string id: The version id that should be reported.
    """

    def __init__(
        self,
        href: str,
        id: str,
        *,
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> None:
        super().__init__(id, status=status, updated=updated)

        self.add_link(href)


class MicroversionDiscovery(DiscoveryBase):
    """A Version element that has microversions.

    Provides some default values and helper methods for creating a microversion
    endpoint version structure. Clients should use this instead of creating
    their own structures.

    :param string href: The url that this entry should point to.
    :param string id: The version id that should be reported.
    :param string min_version: The minimum supported microversion. (optional)
    :param string max_version: The maximum supported microversion. (optional)
    """

    def __init__(
        self,
        href: str,
        id: str,
        *,
        min_version: str = '',
        max_version: str = '',
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> None:
        super().__init__(id, status=status, updated=updated)

        self.add_link(href)

        self.min_version = min_version
        self.max_version = max_version

    @property
    def min_version(self) -> str:
        result: str = self.get('min_version', '')
        return result

    @min_version.setter
    def min_version(self, value: str) -> None:
        self['min_version'] = value

    @property
    def max_version(self) -> str:
        result: str = self.get('max_version', '')
        return result

    @max_version.setter
    def max_version(self, value: str) -> None:
        self['max_version'] = value


class NovaMicroversionDiscovery(DiscoveryBase):
    """A Version element with nova-style microversions.

    Provides some default values and helper methods for creating a microversion
    endpoint version structure. Clients should use this instead of creating
    their own structures.

    :param href: The url that this entry should point to.
    :param string id: The version id that should be reported.
    :param string min_version: The minimum microversion supported. (optional)
    :param string version: The maximum microversion supported. (optional)
    """

    def __init__(
        self,
        href: str,
        id: str,
        *,
        min_version: str = '',
        version: str = '',
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> None:
        super().__init__(id, status=status, updated=updated)

        self.add_link(href)

        self.min_version = min_version
        self.version = version

    @property
    def min_version(self) -> str:
        result: str = self.get('min_version', '')
        return result

    @min_version.setter
    def min_version(self, value: str) -> None:
        if value:
            self['min_version'] = value

    @property
    def version(self) -> str:
        result: str = self.get('version', '')
        return result

    @version.setter
    def version(self, value: str) -> None:
        if value:
            self['version'] = value


class V2Discovery(DiscoveryBase):
    """A Version element for a V2 identity service endpoint.

    Provides some default values and helper methods for creating a v2.0
    endpoint version structure. Clients should use this instead of creating
    their own structures.

    :param string href: The url that this entry should point to.
    :param string id: The version id that should be reported. (optional)
                      Defaults to 'v2.0'.
    :param bool html: Add HTML describedby links to the structure.
    :param bool pdf: Add PDF describedby links to the structure.

    """

    _DESC_URL = 'https://developer.openstack.org/api-ref/identity/v2/'

    def __init__(
        self,
        href: str,
        id: str = 'v2.0',
        *,
        html: bool = True,
        pdf: bool = True,
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ):
        super().__init__(id, status=status, updated=updated)

        self.add_link(href)

        if html:
            self.add_html_description()
        if pdf:
            self.add_pdf_description()

    def add_html_description(self) -> None:
        """Add the HTML described by links.

        The standard structure includes a link to a HTML document with the
        API specification. Add it to this entry.
        """
        self.add_link(
            href=self._DESC_URL + 'content',
            rel='describedby',
            type='text/html',
        )

    def add_pdf_description(self) -> None:
        """Add the PDF described by links.

        The standard structure includes a link to a PDF document with the
        API specification. Add it to this entry.
        """
        self.add_link(
            href=self._DESC_URL + 'identity-dev-guide-2.0.pdf',
            rel='describedby',
            type='application/pdf',
        )


class V3Discovery(DiscoveryBase):
    """A Version element for a V3 identity service endpoint.

    Provides some default values and helper methods for creating a v3
    endpoint version structure. Clients should use this instead of creating
    their own structures.

    :param href: The url that this entry should point to.
    :param string id: The version id that should be reported. (optional)
                      Defaults to 'v3.0'.
    :param bool json: Add JSON media-type elements to the structure.
    :param bool xml: Add XML media-type elements to the structure.
    """

    def __init__(
        self,
        href: str,
        id: str = 'v3.0',
        *,
        json: bool = True,
        xml: bool = True,
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ):
        super().__init__(id, status=status, updated=updated)

        self.add_link(href)

        if json:
            self.add_json_media_type()
        if xml:
            self.add_xml_media_type()

    def add_json_media_type(self) -> None:
        """Add the JSON media-type links.

        The standard structure includes a list of media-types that the endpoint
        supports. Add JSON to the list.
        """
        self.add_media_type(
            base='application/json',
            type='application/vnd.openstack.identity-v3+json',
        )

    def add_xml_media_type(self) -> None:
        """Add the XML media-type links.

        The standard structure includes a list of media-types that the endpoint
        supports. Add XML to the list.
        """
        self.add_media_type(
            base='application/xml',
            type='application/vnd.openstack.identity-v3+xml',
        )


class DiscoveryList(dict[str, ty.Any]):
    """A List of version elements.

    Creates a correctly structured list of identity service endpoints for
    use in testing with discovery.

    :param string href: The url that this should be based at.
    :param bool v2: Add a v2 element.
    :param bool v3: Add a v3 element.
    :param string v2_status: The status to use for the v2 element.
    :param DateTime v2_updated: The update time to use for the v2 element.
    :param bool v2_html: True to add a html link to the v2 element.
    :param bool v2_pdf: True to add a pdf link to the v2 element.
    :param string v3_status: The status to use for the v3 element.
    :param DateTime v3_updated: The update time to use for the v3 element.
    :param bool v3_json: True to add a html link to the v2 element.
    :param bool v3_xml: True to add a pdf link to the v2 element.
    """

    TEST_URL = 'http://keystone.host:5000/'

    def __init__(
        self,
        href: str | None = None,
        v2: bool = True,
        v3: bool = True,
        v2_id: str = 'v2.0',
        v3_id: str = 'v3.0',
        v2_status: str | None = None,
        v2_updated: datetime.datetime | None = None,
        v2_html: bool = True,
        v2_pdf: bool = True,
        v3_status: str | None = None,
        v3_updated: datetime.datetime | None = None,
        v3_json: bool = True,
        v3_xml: bool = True,
    ) -> None:
        super().__init__(versions={'values': []})

        href = href or self.TEST_URL

        if v2:
            v2_href = href.rstrip('/') + '/v2.0'
            self.add_v2(
                v2_href,
                id=v2_id,
                status=v2_status,
                updated=v2_updated,
                html=v2_html,
                pdf=v2_pdf,
            )

        if v3:
            v3_href = href.rstrip('/') + '/v3'
            self.add_v3(
                v3_href,
                id=v3_id,
                status=v3_status,
                updated=v3_updated,
                json=v3_json,
                xml=v3_xml,
            )

    @property
    def versions(self) -> list[DiscoveryBase]:
        versions: list[DiscoveryBase] = self['versions']['values']
        return versions

    def add_version(self, version: DiscoveryBase) -> None:
        """Add a new version structure to the list.

        :param dict version: A new version structure to add to the list.
        """
        self.versions.append(version)

    def add_v2(
        self,
        href: str,
        id: str = 'v2.0',
        *,
        html: bool = True,
        pdf: bool = True,
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> V2Discovery:
        """Add a v2 version to the list.

        The parameters are the same as V2Discovery.
        """
        obj = V2Discovery(
            href, id, html=html, pdf=pdf, status=status, updated=updated
        )
        self.add_version(obj)
        return obj

    def add_v3(
        self,
        href: str,
        id: str = 'v3.0',
        *,
        json: bool = True,
        xml: bool = True,
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> V3Discovery:
        """Add a v3 version to the list.

        The parameters are the same as V3Discovery.
        """
        obj = V3Discovery(
            href, id, json=json, xml=xml, status=status, updated=updated
        )
        self.add_version(obj)
        return obj

    def add_microversion(
        self,
        href: str,
        id: str,
        *,
        min_version: str = '',
        max_version: str = '',
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> MicroversionDiscovery:
        """Add a microversion version to the list.

        The parameters are the same as MicroversionDiscovery.
        """
        obj = MicroversionDiscovery(
            href,
            id,
            min_version=min_version,
            max_version=max_version,
            status=status,
            updated=updated,
        )
        self.add_version(obj)
        return obj

    def add_nova_microversion(
        self,
        href: str,
        id: str,
        *,
        min_version: str = '',
        version: str = '',
        status: str | None = None,
        updated: datetime.datetime | None = None,
    ) -> NovaMicroversionDiscovery:
        """Add a nova microversion version to the list.

        The parameters are the same as NovaMicroversionDiscovery.
        """
        obj = NovaMicroversionDiscovery(
            href,
            id,
            min_version=min_version,
            version=version,
            status=status,
            updated=updated,
        )
        self.add_version(obj)
        return obj
