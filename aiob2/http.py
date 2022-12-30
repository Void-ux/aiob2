from __future__ import annotations

import aiohttp
import asyncio
import base64
import hashlib
import sys
from typing import TYPE_CHECKING, TypeVar, Coroutine, NamedTuple, TypedDict, Union, Optional, Literal, Tuple, Dict, Any
from urllib.parse import quote as _uriquote

from yarl import URL

from .errors import (
    RateLimited,
    Unauthorized,
    Forbidden,
    NotFound,
    BackblazeServerError,
    HTTPException
)
from .models.file import UploadPayload, PartialFilePayload
from .models.account import AccountAuthorizationPayload, Permissions
from .utils import MISSING

if TYPE_CHECKING:
    T = TypeVar('T')
    Response = Coroutine[Any, Any, T]

HTTPVerb = Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH']


__all__ = ('HTTPClient', )


class UploadURLPayload(TypedDict):
    bucketId: str
    uploadUrl: str
    authorizationToken: str


class BucketUploadInfo(NamedTuple):
    url: str
    token: str


class Route:
    """A helper class for instantiating a HTTP method to Backblaze

    Parameters
    -----------
    method: :class:`str`
        The HTTP method you wish to perform, e.g. ``"POST"``
    path: :class:`str`
        The prepended path to the API endpoint you with to target. e.g. ``"/b2_authorize_account"``
    override_base: Optional[:class:`str`]
        The URL to override the base with. Useful for the download/upload Backblaze routes.
    action: :class:`str`
        The action being performed, used to tell which parts of the header to re-generate upon expiration.
    parameters: Any
        This is a special cased kwargs. Anything passed to these will substitute it's key to value in the `path`.
    """

    BASE: str = 'https://api.backblazeb2.com/b2api/v2'

    def __init__(
        self,
        method: Literal['GET', 'POST', 'PUT', 'DELETE'],
        path: str,
        *,
        override_base: Optional[str] = None,
        action: Literal['upload', 'download', 'authorize_account', 'other'],
        **parameters: Any
    ) -> None:
        self.method = method
        self.path = path
        self.parameters = parameters
        url = (override_base or self.BASE) + self.path
        if parameters:
            url = url.format_map({k: _uriquote(v) if isinstance(v, str) else v for k, v in self.parameters.items()})

        self.action = action
        self.url: URL = URL(url, encoded=True)


async def json_or_bytes(response: aiohttp.ClientResponse, route: Route) -> Union[Dict[str, Any], bytes]:
    if route.path == '/b2api/v2/b2_download_file_by_id' or route.path.startswith('/file/'):
        return await response.read()
    else:
        return await response.json()


class HTTPClient:
    def __init__(
        self,
        application_key_id: str,
        application_key: str,
        session: Optional[aiohttp.ClientSession] = None
    ):
        self._application_key_id = application_key_id
        self._application_key = application_key
        self._session = session

        self._account_id: str = MISSING
        self._authorization_token: str = MISSING
        self._allowed: Permissions = MISSING
        self._api_url: str = MISSING
        self._download_url: str = MISSING
        self._recommended_part_size: int = MISSING
        self._absolute_minimum_part_size: int = MISSING
        self._s3_api: str = MISSING

        # mappings of bucket ids and their respective
        # upload urls and tokens
        self._upload_urls: Dict[str, BucketUploadInfo] = {}

        # used when first authorizing to update the MISSING headers
        # and when they're refreshed, i.e. when they expire
        self.refresh_headers: bool = True

        # prevent circular import
        from . import __version__
        user_agent = 'aiob2 (https://github.com/Void-ux/aiob2 {0}) Python/{0[0]}.{0[1]} aiohttp/{1}'
        self.user_agent: str = user_agent.format(__version__, sys.version_info, aiohttp.__version__)

    @staticmethod
    async def _generate_session() -> aiohttp.ClientSession:
        """Creates an :class:`aiohttp.ClientSession` for use in the http client.

        Returns
        --------
        :class:`aiohttp.ClientSession`
            The underlying client session we use.

        .. note::
            This method must be a coroutine to avoid the deprecation warning of Python 3.9+.
        """
        return aiohttp.ClientSession()

    async def _close(self) -> None:
        """This method will close the internal client session to ensure a clean exit."""

        if self._session is not None:
            await self._session.close()

    async def _authorize_account(self) -> None:
        """Used to log in to the B2 API."""

        id_and_key = f'{self._application_key_id}:{self._application_key}'.encode()
        basic_auth_string = 'Basic ' + base64.b64encode(id_and_key).decode()
        headers = {
            'Authorization': basic_auth_string
        }

        route = Route('GET', '/b2_authorize_account', action='authorize_account')
        response: AccountAuthorizationPayload = await self.request(route, headers=headers)

        self._account_id: str = response['accountId']
        self._authorization_token: str = response['authorizationToken']
        self._allowed: Permissions = response['allowed']
        self._api_url: str = response['apiUrl']
        self._download_url: str = response['downloadUrl']
        self._recommended_part_size: int = response['recommendedPartSize']
        self._absolute_minimum_part_size: int = response['absoluteMinimumPartSize']
        self._s3_api: str = response['s3ApiUrl']

    async def _get_upload_url(self, bucket_id: str) -> BucketUploadInfo:
        """Fetches the upload URL and token for a specific bucket.

        Parameters
        -----------
        bucket_id: str
            The ID of the bucket to get the upload info for.

        Returns
        ---------
        BucketUploadInfo
            The URL for uploading files, and the authorization token to use with it.
        """

        route = Route('GET', '/b2api/v2/b2_get_upload_url', override_base=self._api_url, action='other')
        headers = {
            'Authorization': self._authorization_token
        }
        params = {
            'bucketId': bucket_id
        }
        response: UploadURLPayload = await self.request(route, headers=headers, params=params)

        return BucketUploadInfo(response['uploadUrl'], response['authorizationToken'])
    
    def _refresh_headers(self, route: Route, headers: Dict[str, Any], *, bucket_id: Optional[str]) -> Tuple[Route, Dict[str, Any]]:
        if route.action == 'upload':
            assert bucket_id is not None
            upload_info = self._upload_urls[bucket_id]
            headers['Authorization'] = upload_info.token
            route = Route('POST', '', override_base=upload_info.url, action='upload')
        elif route.action == 'download':
            headers['Authorization'] = self._authorization_token
            route = Route('GET', route.path, override_base=self._download_url, action='download', **route.parameters)
        elif route.action == 'other':
            headers['Authorization'] = self._authorization_token
            route = Route('GET', route.path, override_base=self._api_url, action='other')
    
        return route, headers

    async def request(self, route: Route, *, bucket_id: Optional[str] = None, **kwargs: Any) -> Any:
        if self._session is None:
            self._session = await self._generate_session()

        if self._account_id is MISSING and route.path != '/b2_authorize_account':  # prevent recursion death loop
            await self._authorize_account()

        headers: Dict[str, str] = kwargs.pop('headers')
        headers['User-Agent'] = self.user_agent

        for tries in range(5):
            print(f'Route: {route.url}')
            # authorize_account uses the app_id/key, which don't change
            if self.refresh_headers and route.action != 'authorize_account':
                route, headers = self._refresh_headers(route, headers, bucket_id=bucket_id)

            async with self._session.request(route.method, route.url, headers=headers, **kwargs) as response:
                data = await json_or_bytes(response, route)

                if 300 > response.status >= 200:
                    if route.path != '/b2_authorize_account':
                        self.refresh_headers = False
                    if isinstance(data, bytes):
                        return data, response.headers
                    return data

                # appease type checker; json_or_bytes will
                # only return bytes if response.ok
                assert isinstance(data, dict)

                # we are being rate limited
                if response.status == 429:
                    raise RateLimited(response, data)

                if response.status in {408, 500, 503}:
                    await asyncio.sleep(1 + tries * 2)

                if response.status == 401:
                    if route.path == '/b2_authorize_account':
                        raise Unauthorized(response, data)
                    if data['code'] in ('expired_auth_token', 'bad_auth_token'):
                        self.refresh_headers = True
                        await self._authorize_account()

                        if route.action == 'upload':
                            assert bucket_id is not None
                            self._upload_urls[bucket_id] = await self._get_upload_url(bucket_id)

                    continue  # note: this may retry an extra pointless 3 times

                if response.status == 403:
                    raise Forbidden(response, data)
                elif response.status == 404:
                    raise NotFound(response, data)
                elif response.status >= 500:
                    raise BackblazeServerError(response, data)
                else:
                    raise HTTPException(response, data)

    async def upload_file(
            self,
            *,
            content_bytes: bytes,
            content_type: str,
            file_name: str,
            bucket_id: str
    ) -> Response[UploadPayload]:
        bucket_upload_info = self._upload_urls.get(bucket_id)
        if bucket_upload_info is None:
            bucket_upload_info = await self._get_upload_url(bucket_id)
            self._upload_urls[bucket_id] = bucket_upload_info

        headers = {
            'Authorization': bucket_upload_info.token,
            'X-Bz-File-Name': file_name,
            'Content-Type': content_type,
            'X-Bz-Content-Sha1': hashlib.sha1(content_bytes).hexdigest()
        }
        route = Route('POST', '', override_base=bucket_upload_info.url, action='upload')
        return self.request(route, bucket_id=bucket_id, headers=headers, data=content_bytes)

    def delete_file(self, *, file_name: str, file_id: str) -> Response[PartialFilePayload]:
        route = Route('GET', '/b2api/v2/b2_delete_file_version', override_base=self._api_url, action='other')
        headers = {
            'Authorization': self._authorization_token
        }
        params = {
            'fileName': file_name,
            'fileId': file_id
        }
        return self.request(route, headers=headers, params=params)

    def download_file_by_id(
            self,
            *,
            file_id: str,
            content_disposition: Optional[str] = None,
            content_language: Optional[str] = None,
            expires: Optional[str] = None,
            cache_control: Optional[str] = None,
            content_encoding: Optional[str] = None,
            content_type: Optional[str] = None,
            server_side_encryption: Optional[str] = None
    ) -> Response[Tuple[bytes, Dict[str, Any]]]:
        headers = {
            'Authorization': self._authorization_token,
            'b2ContentDisposition': content_disposition,
            'b2ContentLanguage': content_language,
            'b2Expires': expires,
            'b2CacheControl': cache_control,
            'b2ContentEncoding': content_encoding,
            'b2ContentType': content_type,
            'serverSideEncryption': server_side_encryption
        }
        headers = {key: value for key, value in headers.items() if value is not None}
        params = {
            'fileId': file_id
        }
        route = Route(
            'GET',
            '/b2api/v2/b2_download_file_by_id',
            override_base=self._download_url,
            action='download'
        )

        return self.request(route, headers=headers, params=params)

    def download_file_by_name(
            self,
            *,
            file_name: str,
            bucket_name: str,
            content_disposition: Optional[str] = None,
            content_language: Optional[str] = None,
            expires: Optional[str] = None,
            cache_control: Optional[str] = None,
            content_encoding: Optional[str] = None,
            content_type: Optional[str] = None,
            server_side_encryption: Optional[str] = None
    ) -> Response[Tuple[bytes, Dict[str, Any]]]:
        headers = {
            'Authorization': self._authorization_token,
            'b2ContentDisposition': content_disposition,
            'b2ContentLanguage': content_language,
            'b2Expires': expires,
            'b2CacheControl': cache_control,
            'b2ContentEncoding': content_encoding,
            'b2ContentType': content_type,
            'serverSideEncryption': server_side_encryption
        }
        headers = {key: value for key, value in headers.items() if value is not None}
        route = Route(
            'GET',
            '/file/{bucket_name}/{file_name}',
            override_base=self._download_url,
            bucket_name=bucket_name,
            file_name=file_name,
            action='download'
        )

        return self.request(route, headers=headers)
