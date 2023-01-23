from __future__ import annotations

import aiohttp
import asyncio
import base64
import hashlib
import sys
import logging
import datetime
import re
from typing import TYPE_CHECKING, TypeVar, Coroutine, NamedTuple, TypedDict, Union, Optional, Literal, Tuple, List, Dict, Any
from urllib.parse import quote, quote_plus

from yarl import URL

from .errors import (
    RateLimited,
    Unauthorized,
    Forbidden,
    NotFound,
    BackblazeServerError,
    HTTPException
)
from .models.file import UploadPayload, PartialFilePayload, LargeFilePartPayload
from .models.account import AccountAuthorizationPayload, Permissions
from .utils import MISSING

if TYPE_CHECKING:
    T = TypeVar('T')
    Response = Coroutine[Any, Any, T]

__all__ = ('HTTPClient', )

log = logging.getLogger(__name__)

HTTPVerb = Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH']


class UploadURLPayload(TypedDict):
    bucketId: str
    uploadUrl: str
    authorizationToken: str


class LargeFileUploadURLPayload(TypedDict):
    fileId: str
    uploadUrl: str
    authorizationToken: str


class BucketUploadInfo(NamedTuple):
    url: str
    token: str


class LargeFileUploadInfo(NamedTuple):
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
    base: Optional[:class:`str`]
        The URL to override the base with. Useful for the b2_download_file_by_name/b2_upload_file Backblaze routes.
    parameters: Any
        This is a special cased kwargs. Anything passed to these will substitute it's key to value in the `path`.
    """

    BASE: str = 'https://api.backblazeb2.com/b2api/v2'

    def __init__(
        self,
        method: Literal['GET', 'POST', 'PUT', 'DELETE'],
        path: str,
        *,
        base: Optional[str] = None,
        **parameters: Any
    ) -> None:
        self.method: Literal['GET', 'POST', 'PUT', 'DELETE'] = method
        self.path = path
        self.parameters = parameters
        url = (base or self.BASE) + self.path
        if parameters:
            url = url.format_map({k: quote(v) if isinstance(v, str) else v for k, v in self.parameters.items()})

        self.url: URL = URL(url, encoded=True)

    def __repr__(self) -> str:
        return f'{self.method} {str(self.url)}'


async def json_or_bytes(response: aiohttp.ClientResponse, route: Route) -> Union[Dict[str, Any], bytes]:
    if response.headers['Content-Type'].lower() in ('application/json;charset=utf-8', 'application/json'):
        return await response.json()
    else:
        return await response.read()


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

        self._upload_urls: Dict[str, BucketUploadInfo] = {}
        self._large_upload_urls: Dict[str, LargeFileUploadInfo] = {}

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

        route = Route('GET', '/b2_authorize_account')
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
        """Fetches the upload URL and token for a specific bucket or a large file.

        Parameters
        -----------
        bucket_id: :class:`str`
            The ID of the bucket to get the upload info for.

        Returns
        ---------
        :class:`BucketUploadInfo`
            The URL for uploading files or file parts, and the authorization token to use with it.
        """

        headers = {
            'Authorization': self._authorization_token
        }
        params = {
            'bucketId': bucket_id
        }

        route = Route('GET', '/b2api/v2/b2_get_upload_url', base=self._api_url)
        response: UploadURLPayload = await self.request(route, headers=headers, params=params)
        return BucketUploadInfo(response['uploadUrl'], response['authorizationToken'])

    async def start_large_file(
        self,
        bucket_id: str,
        file_name: str,
        content_type: str,
        upload_timestamp: Optional[datetime.datetime],
        comments: Optional[Dict[str, str]]
    ) -> UploadPayload:
        """Prepares for uploading every part of a large file."""

        headers = {
            'Authorization': self._authorization_token
        }
        data: Dict[Any, Any] = {
            'bucketId': bucket_id,
            'fileName': file_name,
            'contentType': content_type
        }

        if upload_timestamp:
            assert datetime.datetime.now() >= upload_timestamp, 'Future dates for upload timestamps are not supported'

            timestamp = int(upload_timestamp.timestamp() * 1000)
            assert timestamp.bit_length() <= 64, \
                'The upload timestamp must be 64 bits when turned into a UNIX timestamp in milliseconds'

            headers['X-Bz-Custom-Upload-Timestamp'] = str(timestamp)
        if comments:
            data['fileInfo'] = comments

        # Backblaze allows future dates for some accounts,
        # so pre-checking it isn't viable
        if upload_timestamp:
            timestamp = int(upload_timestamp.timestamp() * 1000)
            assert timestamp.bit_length() <= 64, \
                'The upload timestamp must be 64 bits when turned into a UNIX timestamp in milliseconds.'
            data['X-Bz-Custom-Upload-Timestamp'] = str(timestamp)

        route = Route('POST', '/b2api/v2/b2_start_large_file', base=self._api_url)
        return await self.request(route, json=data, headers=headers)

    async def _get_upload_part_url(self, file_id: str) -> LargeFileUploadInfo:
        """Fetches an upload URL and token for uploading parts of a large file.

        Parameters
        -----------
        file_id: :class:`str`
            The ID of the large file.

        Returns
        ---------
        :class:`LargeFileUploadInfo`
            The URL for uploading files, and the authorization token to use with it.
        """

        headers = {
            'Authorization': self._authorization_token
        }
        params = {
            'fileId': file_id
        }

        route = Route('GET', '/b2api/v2/b2_get_upload_part_url', base=self._api_url)
        response: LargeFileUploadURLPayload = await self.request(route, headers=headers, params=params)
        return LargeFileUploadInfo(response['uploadUrl'], response['authorizationToken'])

    async def request(
        self,
        route: Route,
        *,
        bucket_id: Optional[str] = None,
        file_id: Optional[str] = None,
        **kwargs: Any
    ) -> Any:
        """Send a HTTP request to the `route.url`, with HTTP error code handling defined by the B2 API docs.

        Parameters
        ----------
        route: :class:`Route`
            The HTTP method and URL.
        bucket_id: Optional[:class:`str`]
            The bucket ID being uploaded to, only specified when called from `HTTPClient.upload_file`.
        **kwargs: Any
            kwargs to pass to `aiohttp.ClientSession.request()`, any of `headers`, `params`, `data`, `json`.
        """

        # we'll use this variable to tell whether or not to refresh an upload
        # url url/token, or the account's api url/token. this'll only be `True`
        # if we're using b2_upload_file or b2_upload_part
        uploading_file = bucket_id is not None or file_id is not None

        if self._session is None:
            self._session = await self._generate_session()

        headers: Dict[str, str] = kwargs.pop('headers')
        headers['User-Agent'] = self.user_agent

        # this will only ever happen on the very first self.request
        # luckily, the first route will always use the account authorization
        # token, e.g. b2_get_upload_url, download_file_by_x, etc.
        # only b2_upload_file and b2_upload_part use custom tokens, which must first
        # go through b2_get_upload_(part_)url, so they can't be the first request.
        if headers['Authorization'] is MISSING and route.path != '/b2_authorize_account':
            log.info('Authenticating using static application key')
            await self._authorize_account()
            log.debug('Logged in with account ID %s', self._account_id)
            headers['Authorization'] = self._authorization_token
            route = Route(route.method, route.path, base=self._api_url, **route.parameters)

        for tries in range(5):
            async with self._session.request(route.method, route.url, headers=headers, **kwargs) as response:
                if uploading_file:
                    log.debug(
                        '%s %s with a payload of %s bytes has returned %s',
                        route.method,
                        route.url,
                        len(kwargs['data']),
                        response.status
                    )
                else:
                    log.debug('%s %s has returned %s', route.method, route.url, response.status)

                data = await json_or_bytes(response, route)

                if 300 > response.status >= 200:
                    # for download_file_by_x; the headers contain info about the files
                    if isinstance(data, bytes):
                        return data, response.headers
                    return data

                # appease type checker; json_or_bytes will
                # only return bytes if response.ok which'll
                # be handled in the `if` statement above
                assert isinstance(data, dict)

                # we are being rate limited
                if response.status == 429:
                    raise RateLimited(response, data)

                if response.status in {408, 500, 503}:
                    # Backblaze recommends calling b2_get_upload_url again
                    # this wasn't shortened into a single 'if' to preserve readability
                    if response.status == 503 and uploading_file:
                        pass
                    else:
                        log.warning(
                            '%s %s returned %s (%s), sleeping for %s',
                            route.method,
                            route.url,
                            response.status,
                            data['code'],
                            1 + tries * 2
                        )
                        await asyncio.sleep(1 + tries * 2)

                if response.status == 401 or (response.status == 503 and uploading_file):
                    if route.path == '/b2_authorize_account':
                        raise Unauthorized(response, data)

                    # (auth token has expired, auth token was not valid to begin with, internal server error i.e. 503)
                    if data['code'] in ('expired_auth_token', 'bad_auth_token', 'service_unavailable'):
                        log.info(
                            '%s %s has returned %s (%s), most likely because it expired, attempting to re-authenticate',
                            route.method,
                            route.url,
                            response.status,
                            data['code']
                        )

                        # b2_upload_file, b2_upload_part
                        if uploading_file:
                            if bucket_id is not None:
                                upload_info = self._upload_urls[bucket_id] = await self._get_upload_url(bucket_id)
                            elif file_id is not None:
                                upload_info = self._large_upload_urls[file_id] = await self._get_upload_part_url(file_id)
                            # reset the upload URL and token and retry
                            headers['Authorization'] = upload_info.token  # type: ignore
                            route = Route(
                                route.method,
                                route.path,
                                base=upload_info.url,  # type: ignore
                                parameters=route.parameters
                            )

                            log.info('Re-authenticated upload URL and upload URL token')
                        else:
                            # download_by_file_x also uses the account authorization token
                            await self._authorize_account()
                            headers['Authorization'] = self._authorization_token

                            log.info('Re-authenticated account authorization token')
                    else:
                        raise Unauthorized(response, data)

                    continue

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
        file_name: str,
        content_bytes: bytes,
        bucket_id: str,
        content_type: str,
        content_disposition: Optional[str],
        content_language: Optional[List[str]],
        expires: Optional[datetime.datetime],
        content_encoding: Optional[List[Literal['gzip', 'compress', 'deflate', 'identity']]],
        comments: Optional[Dict[str, str]],
        upload_timestamp: Optional[datetime.datetime],
        server_side_encryption: Optional[Literal['AES256']]
    ) -> Response[UploadPayload]:
        upload_info = self._upload_urls.get(bucket_id)
        if upload_info is None:
            upload_info = await self._get_upload_url(bucket_id)
            self._upload_urls[bucket_id] = upload_info

        headers: Dict[str, Union[str, int]] = {
            'Authorization': upload_info.token,
            'X-Bz-File-Name': quote(file_name),
            'Content-Type': content_type,
            'X-Bz-Content-Sha1': hashlib.sha1(content_bytes).hexdigest()
        }
        if content_disposition:
            reg = re.compile(r'(?P<display>inline|attachment)(?:\s*;\s*filename="(?P<filename>.*)?")?')
            assert reg.search(content_disposition), 'The content_disposition header must be valid, see MDN docs'
            headers['X-Bz-Info-b2-content-disposition'] = quote(content_disposition)
        if content_language:
            headers['X-Bz-Info-b2-content-language'] = quote(', '.join(content_language))
        if expires:
            date = expires.astimezone(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
            headers['X-Bz-Info-b2-expires'] = quote(date)
        if content_encoding:
            headers['X-Bz-Info-b2-content-encoding'] = quote(', '.join(content_encoding))
        if comments:
            key, value = list(comments.items())[0]
            headers[f'X-Bz-Info-{quote_plus(key)}'] = quote(value.encode('utf-8'))
        if upload_timestamp:
            assert datetime.datetime.now() >= upload_timestamp, 'Future dates for upload timestamps are not supported'

            timestamp = int(upload_timestamp.timestamp() * 1000)
            assert timestamp.bit_length() <= 64, \
                'The upload timestamp must be 64 bits when turned into a UNIX timestamp in milliseconds'

            headers['X-Bz-Custom-Upload-Timestamp'] = str(timestamp)
        if server_side_encryption:
            assert server_side_encryption == 'AES256', 'Backblaze currently only supports AES256 server-side encryption'
            headers['X-Bz-Server-Side-Encryption'] = server_side_encryption

        route = Route('POST', '', base=upload_info.url)
        return self.request(route, bucket_id=bucket_id, headers=headers, data=content_bytes)

    async def upload_part(
        self,
        file_id: str,
        part_number: int,
        content_bytes: bytes,
        sha1: str
    ) -> Response[LargeFilePartPayload]:
        upload_info = self._large_upload_urls.get(file_id)
        if upload_info is None:
            upload_info = await self._get_upload_part_url(file_id)
            self._large_upload_urls[file_id] = upload_info

        content_length = len(content_bytes)
        if content_length > self._recommended_part_size:
            log.warning(
                'Upload part %s for file ID %s is over the recommended part size, this may result in longer upload times',
                part_number,
                file_id
            )

        headers = {
            'Authorization': upload_info.token,
            'X-Bz-Part-Number': str(part_number),
            'Content-Length': str(content_length),
            'X-Bz-Content-Sha1': sha1
        }

        route = Route('POST', '', base=upload_info.url)
        return self.request(route, file_id=file_id, headers=headers, data=content_bytes)

    def finish_large_file(self, file_id: str, sha1_list: list[str]) -> Response[UploadPayload]:
        headers = {
            'Authorization': self._authorization_token
        }
        data = {
            'fileId': file_id,
            'partSha1Array': sha1_list
        }

        route = Route('POST', '/b2api/v2/b2_finish_large_file', base=self._api_url)
        return self.request(route, headers=headers, json=data)

    def cancel_large_file(self, file_id: str) -> Response[None]:
        headers = {
            'Authorization': self._authorization_token
        }
        data = {
            'fileId': file_id
        }

        route = Route('POST', '/b2api/v2/b2_cancel_large_file', base=self._api_url)
        return self.request(route, headers=headers, json=data)

    def delete_file(self, *, file_name: str, file_id: str) -> Response[PartialFilePayload]:
        route = Route('POST', '/b2api/v2/b2_delete_file_version', base=self._api_url)
        headers = {
            'Authorization': self._authorization_token
        }
        data = {
            'fileName': file_name,
            'fileId': file_id
        }
        return self.request(route, headers=headers, json=data)

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
            base=self._download_url
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
            base=self._download_url,
            bucket_name=bucket_name,
            file_name=file_name
        )

        return self.request(route, headers=headers)
