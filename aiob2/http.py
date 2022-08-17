from __future__ import annotations

import aiohttp
import base64

from typing import Union, Optional
from .exceptions import codes, B2Error
from .models import B2ConnectionInfo, AuthorisedAccount, UploadData


class HTTPClient:
    def __init__(self, connection_info: B2ConnectionInfo, session: Optional[aiohttp.ClientSession] = None):
        self.connection_info = connection_info
        self._session = session

    @staticmethod
    async def _generate_session() -> aiohttp.ClientSession:
        """This method must be a coroutine to avoid the deprecation warning of Python 3.9+."""
        return aiohttp.ClientSession()

    async def request(
            self,
            url: str,
            *,
            method: str,
            **kwargs) -> Union[Union[dict, aiohttp.ClientResponse], tuple[dict, bytes]]:
        if self._session is None:
            self._session = await self._generate_session()

        if method == 'GET':
            async with self._session.get(url, **kwargs) as r:
                try:
                    json_r = await r.json()
                except aiohttp.ContentTypeError:
                    # When decoding download_file_by_x we do not receive a
                    # ClientResponse that could be converted into a dict
                    # We could assume everything went alright, and end it here
                    return dict(r.headers), await r.read()
        else:
            async with self._session.post(url, **kwargs) as r:
                json_r = await r.json()

        if json_r.get('status') is not None:
            raise codes.get(B2Error(json_r['status'], json_r['code']))(json_r['message'])

        return json_r

    async def authorise_account(self) -> AuthorisedAccount:
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

        r = await self.request(
            'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
            method='GET',
            headers=headers
        )

        return AuthorisedAccount.from_response(r)

    async def get_upload_url(self, bucket_id: str) -> UploadData:
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
        account = await self.authorise_account()

        r = await self.request(
            f'{account.api_url}/b2api/v2/b2_get_upload_url',
            method='GET',
            headers={'Authorization': account.authorisation_token},
            params={'bucketId': bucket_id}
        )

        return UploadData.from_response(r)
