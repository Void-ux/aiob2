import base64
import hashlib
import aiohttp

from typing import Optional, Union

from aiohttp import ClientSession
from .exceptions import codes, B2Error
from .types import *


__all__ = ['upload_file', 'delete_file', 'download_file_by_id', 'download_file_by_name']


async def _http(
        url: str,
        *,
        session: ClientSession,
        method: str,
        **kwargs) -> Union[Union[dict, aiohttp.ClientResponse], tuple[dict, bytes]]:
    if method == 'GET':
        async with session.get(url, **kwargs) as r:
            try:
                json_r = await r.json()
            except aiohttp.ContentTypeError:
                # When decoding download_file_by_x we do not receive a
                # ClientResponse that could be converted into a dict
                # We could assume everything went alright, and end it here
                return dict(r.headers), await r.read()
    else:
        async with session.post(url, **kwargs) as r:
            json_r = await r.json()

    if json_r.get('status') is not None:
        raise codes.get(B2Error(json_r['status'], json_r['code']))(json_r['message'])

    return json_r


async def _authorise_account(
        connection_info: B2ConnectionInfo,
        session: ClientSession
) -> AuthorisedAccount:
    """
    Used to log in to the B2 API.

    ...

    Parameters
    ----------
    connection_info: B2ConnectionInfo
        The app_id and key_id for the HTTP request headers
    session: ClientSession
        The ClientSession to send the HTTP requests with
    Returns
    ---------
    AuthorisedAccount
        An AuthorisedAccount object containing the response data Backblaze sent.
    """
    id_and_key = f'{connection_info.key_id}:{connection_info.app_id}'.encode()
    basic_auth_string = 'Basic ' + base64.b64encode(id_and_key).decode()
    headers = {'Authorization': basic_auth_string}

    r = await _http(
        'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
        session=session,
        method='GET',
        headers=headers
    )

    return AuthorisedAccount.from_response(r)


async def _get_upload_url(
        connection_info: B2ConnectionInfo,
        bucket_id: str,
        session: ClientSession
) -> UploadUrl:
    """
    Gets an upload URL for uploading any files to a specified bucket.

    ...

    Parameters
    -----------
    connection_info: B2ConnectionInfo
        The key_id and the app_id for the account authorisation
    bucket_id: str
        The ID of the bucket to get the upload URL for.
    session: ClientSession
        The ClientSession to send the HTTP requests with.
    Returns
    ---------
    UploadUrl
        An UploadUrl object containing the data Blackblaze sent back.
    """
    account = await _authorise_account(connection_info, session)

    r = await _http(
        f'{account.api_url}/b2api/v2/b2_get_upload_url',
        session=session,
        method='GET',
        headers={'Authorization': account.authorisation_token},
        params={'bucketId': bucket_id}
    )

    return UploadUrl.from_response(r)


async def upload_file(
        *,
        content_bytes: bytes,
        content_type: str,
        file_name: str,
        bucket_id: str,
        session: ClientSession,
        connection_info: B2ConnectionInfo
) -> File:
    """
    Uploads a file to a bucket.

    ...

    Parameters
    -----------
    content_bytes: bytes
        The raw bytes of the file to be uploaded.
    content_type: str
        The content type of the content_bytes, e.g. video/mp4.
    file_name: str
        The name of the file.
    session: ClientSession
        The ClientSession to send the HTTP requests with
    bucket_id: str
        The ID of the bucket to upload to.
    connection_info: B2ConnectionInfo
        The key_id and the app_id for the account authorisation
    Returns
    ---------
    File
        A File object wrapping the data provided by Backblaze.
    """
    upload_url = await _get_upload_url(connection_info, bucket_id, session)

    headers = {
        'Authorization': upload_url.authorisation_token,
        'X-Bz-File-Name': str(file_name),
        'Content-Type': content_type,
        'X-Bz-Content-Sha1': hashlib.sha1(content_bytes).hexdigest()
    }
    r = await _http(str(upload_url), session=session, method='POST', headers=headers, data=content_bytes)

    return File.from_response(r)


async def delete_file(
        file_name: str,
        file_id: str,
        session: ClientSession,
        connection_info: B2ConnectionInfo
) -> DeletedFile:
    """
    Deletes a file from a bucket.

    ...

    Parameters
    -----------
    file_name: str
        The name of the file to delete.
    file_id: str
        The id of the file to delete.
    session: ClientSession
        The ClientSession to send the HTTP requests with.
    connection_info: B2ConnectionInfo
        The key_id and the app_id for the account authorisation.
    Returns
    ---------
    DeletedFile
        Returns a DeletedFile object with the attributes `file_name` and `file_id`.
    """
    account = await _authorise_account(connection_info, session)

    r = await _http(
        f'{account.api_url}/b2api/v2/b2_delete_file_version',
        session=session,
        method='GET',
        params={'fileName': file_name, 'fileId': file_id},
        headers={'Authorization': account.authorisation_token}
    )

    return DeletedFile.from_response(r)


async def _get_download_authorisation(
        account: AuthorisedAccount,
        session: aiohttp.ClientSession,
        bucket_id: str,
        file_name_prefix: str,
        valid_duration_in_seconds: str,
        content_disposition: Optional[str] = None,
        content_language: Optional[str] = None,
        expires: Optional[str] = None,
        cache_control: Optional[str] = None,
        content_encoding: Optional[str] = None,
        content_type: Optional[str] = None
) -> DownloadAuthorisation:
    params = {
        'bucketId': bucket_id,
        'fileNamePrefix': file_name_prefix,
        'validDurationInSeconds': valid_duration_in_seconds,
        'b2ContentDisposition': content_disposition,
        'b2ContentLanguage': content_language,
        'b2Expires': expires,
        'b2CacheControl': cache_control,
        'b2ContentEncoding': content_encoding,
        'b2ContentType': content_type
    }
    params = {key: value for key, value in params.items() if value is not None}

    data = await _http(
        f'{account.api_url}/b2api/v2/b2_get_download_authorization',
        session=session,
        method='GET',
        headers={'Authorization': account.authorisation_token},
        params=params
    )

    return DownloadAuthorisation.from_response(data)


async def download_file_by_id(
        file_id: str,
        session: aiohttp.ClientSession,
        *,
        connection_info: Optional[B2ConnectionInfo] = None,
        content_disposition: Optional[str] = None,
        content_language: Optional[str] = None,
        expires: Optional[str] = None,
        cache_control: Optional[str] = None,
        content_encoding: Optional[str] = None,
        content_type: Optional[str] = None,
        server_side_encryption: Optional[str] = None
) -> DownloadedFile:
    """
    Downloads a file.

    ...

    Parameters
    -----------
        file_id: str
            The file id of the file to be downloaded.
        session: aiohttp.ClientSession
            The ClientSession to send the HTTP requests with.
        connection_info: Optional[B2ConnectionInfo]
            The key_id and the app_id for the account authorisation.
        content_disposition: Optional[str]
            Overrides the current 'b2-content-disposition' specified when the file was uploaded.
        content_language: Optional[str]
            Overrides the current 'b2-content-language' specified when the file was uploaded.
        expires: Optional[str]
            Overrides the current 'b2-expires' specified when the file was uploaded.
        cache_control: Optional[str]
            Overrides the current 'b2-cache-control' specified when the file was uploaded.
        content_encoding: Optional[str]
            Overrides the current 'b2-content-encoding' specified when the file was uploaded.
        content_type: Optional[str]
            Overrides the current 'Content-Type' specified when the file was uploaded.
        server_side_encryption: Optional[str]
            This is requires if the file was uploaded and stored using Server-Side Encryption with Customer-Managed Keys
            (SSE-C)
    Returns
    ---------
    DownloadedFile
        A DownloadedFile object containing the data Backblaze sent.
    """
    account = await _authorise_account(connection_info, session)

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

    data = await _http(
        f'{account.download_url}/b2api/v2/b2_download_file_by_id',
        session=session,
        method='GET',
        headers=headers,
        params={'fileId': file_id}
    )
    return DownloadedFile.from_response(data[1], data[0])


async def download_file_by_name(
        file_name: str,
        bucket_name: str,
        session: aiohttp.ClientSession,
        *,
        connection_info: Optional[B2ConnectionInfo] = None,
        content_disposition: Optional[str] = None,
        content_language: Optional[str] = None,
        expires: Optional[str] = None,
        cache_control: Optional[str] = None,
        content_encoding: Optional[str] = None,
        content_type: Optional[str] = None,
        server_side_encryption: Optional[str] = None
) -> DownloadedFile:
    """
    Downloads a file.

    ...

    Parameters
    -----------
        file_name: Optional[str]
            The file name of the file to be downloaded.
        bucket_name: Optional[str]
            The bucket name of the file to be downloaded. This should only be specified if you have specified file_name
            and not file_id.
        session: aiohttp.ClientSession
            The ClientSession to send the HTTP requests with.
        connection_info: Optional[B2ConnectionInfo]
            The key_id and the app_id for the account authorisation.
        content_disposition: Optional[str]
            Overrides the current 'b2-content-disposition' specified when the file was uploaded.
        content_language: Optional[str]
            Overrides the current 'b2-content-language' specified when the file was uploaded.
        expires: Optional[str]
            Overrides the current 'b2-expires' specified when the file was uploaded.
        cache_control: Optional[str]
            Overrides the current 'b2-cache-control' specified when the file was uploaded.
        content_encoding: Optional[str]
            Overrides the current 'b2-content-encoding' specified when the file was uploaded.
        content_type: Optional[str]
            Overrides the current 'Content-Type' specified when the file was uploaded.
        server_side_encryption: Optional[str]
            This is requires if the file was uploaded and stored using Server-Side Encryption with Customer-Managed Keys
            (SSE-C)
    Returns
    ---------
    DownloadedFile
        A DownloadedFile object containing the data Backblaze sent.
    """

    account = await _authorise_account(connection_info, session)

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

    data = await _http(
        f'{account.download_url}/file/{bucket_name}/{file_name}',
        session=session,
        method='GET',
        headers=headers,
    )

    return DownloadedFile.from_response(data[1], data[0])
