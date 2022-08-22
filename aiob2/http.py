import aiohttp
import base64
import hashlib

from typing import Optional, Dict, Literal, Any, Tuple
from urllib.parse import quote as _uriquote
from .exceptions import codes, B2Error, B2Exception
from .models import *

HTTPVerb = Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH']


__all__ = ('HTTPClient', )


class Route:
    __slots__ = (
        "verb",
        "path",
        "url",
    )

    def __init__(self, verb: HTTPVerb, api_url: str, path: str, **params: Any) -> None:
        self.verb: HTTPVerb = verb
        self.path: str = path
        url = api_url + path
        if params:
            url = url.format_map({k: _uriquote(v) if isinstance(v, str) else v for k, v in params.items()})
        self.url: str = url


class HTTPClient:
    def __init__(self, connection_info: B2ConnectionInfo, session: Optional[aiohttp.ClientSession] = None):
        self.connection_info = connection_info
        self._session = session

    @staticmethod
    async def _generate_session() -> aiohttp.ClientSession:
        """This method must be a coroutine to avoid the deprecation warning of Python 3.9+."""
        return aiohttp.ClientSession()

    async def request(self, route: Route, **kwargs) -> Dict:
        if self._session is None:
            self._session = await self._generate_session()

        async with self._session.request(route.verb, route.url, **kwargs) as response:
            data = await response.json()

            if not response.ok:
                try:
                    raise codes[(B2Error(response.status, data['code']))](data['message'])
                except KeyError:
                    raise B2Exception(response.status, data['code']) from None  # prevent chaining the KeyError as a cause

        return data

    async def _download_file(self, url: str, **kwargs) -> Tuple[Dict, bytes]:
        """Separate method for downloading files, as we need to read() this"""
        if self._session is None:
            self._session = await self._generate_session()

        async with self._session.get(url, **kwargs) as response:
            if not response.ok:
                data = await response.json()
                try:
                    raise codes[(B2Error(response.status, data['code']))](data['message'])
                except KeyError:
                    raise B2Exception(response.status, data['code']) from None  # prevent chaining the KeyError as a cause

            return dict(response.headers), await response.read()

    async def _authorise_account(self) -> AuthorisedAccount:
        """
        Used to log in to the B2 API.

        ...

        Returns
        ---------
        AuthorisedAccount
            An AuthorisedAccount object containing the response data Backblaze sent.
        """
        id_and_key = f'{self.connection_info.key_id}:{self.connection_info.app_id}'.encode()
        basic_auth_string = 'Basic ' + base64.b64encode(id_and_key).decode()
        headers = {'Authorization': basic_auth_string}

        route = Route('GET', 'https://api.backblazeb2.com/b2api/v2', '/b2_authorize_account')
        r = await self.request(route=route, headers=headers)

        return AuthorisedAccount.from_response(r)

    async def _get_upload_url(self, bucket_id: str) -> UploadData:
        """
        Gets an upload URL for uploading any files to a specified bucket.

        ...

        Parameters
        -----------
        bucket_id: str
            The ID of the bucket to get the upload URL for.
        Returns
        ---------
        UploadData
            An UploadData object containing the data Blackblaze sent back.
        """
        account = await self._authorise_account()

        route = Route('GET', account.api_url, '/b2api/v2/b2_get_upload_url')
        r = await self.request(route, headers={'Authorization': account.authorisation_token}, params={'bucketId': bucket_id})

        return UploadData.from_response(r)

    async def _upload_file(
            self,
            *,
            content_bytes: bytes,
            content_type: str,
            file_name: str,
            bucket_id: str
    ) -> Dict:
        upload_url = await self._get_upload_url(bucket_id)

        headers = {
            'Authorization': upload_url.authorisation_token,
            'X-Bz-File-Name': str(file_name),
            'Content-Type': content_type,
            'X-Bz-Content-Sha1': hashlib.sha1(content_bytes).hexdigest()
        }
        route = Route('POST', upload_url.upload_url, '')
        data = await self.request(route=route, headers=headers, data=content_bytes)

        return data

    async def _delete_file(self, *, file_name: str, file_id: str) -> Dict:
        account = await self._authorise_account()

        route = Route('GET', account.api_url, '/b2api/v2/b2_delete_file_version')
        data = await self.request(
            route=route,
            params={'fileName': file_name, 'fileId': file_id},
            headers={'Authorization': account.authorisation_token}
        )

        return data

    async def download_file_by_id(
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
    ) -> Tuple[Dict, bytes]:

        account = await self._authorise_account()

        headers = {
            'Authorization': account.authorisation_token,
            'b2ContentDisposition': content_disposition,
            'b2ContentLanguage': content_language,
            'b2Expires': expires,
            'b2CacheControl': cache_control,
            'b2ContentEncoding': content_encoding,
            'b2ContentType': content_type,
            'serverSideEncryption': server_side_encryption
        }
        headers = {key: value for key, value in headers.items() if value is not None}

        data = await self._download_file(
            f'{account.download_url}/b2api/v2/b2_download_file_by_id',
            headers=headers,
            params={'fileId': file_id}
        )

        return data

    async def download_file_by_name(
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
    ) -> Tuple[Dict, bytes]:
        account = await self._authorise_account()

        headers = {
            'Authorization': account.authorisation_token,
            'b2ContentDisposition': content_disposition,
            'b2ContentLanguage': content_language,
            'b2Expires': expires,
            'b2CacheControl': cache_control,
            'b2ContentEncoding': content_encoding,
            'b2ContentType': content_type,
            'serverSideEncryption': server_side_encryption
        }
        headers = {key: value for key, value in headers.items() if value is not None}

        data = await self._download_file(
            f'{account.download_url}/file/{bucket_name}/{file_name}',
            headers=headers
        )

        return data
