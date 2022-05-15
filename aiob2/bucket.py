import base64
import hashlib

from aiohttp import ClientSession
from .exceptions import codes, B2Error
from .types import *


async def http(
        url: str,
        *,
        session: ClientSession,
        method: str,
        **kwargs) -> dict:
    if method == 'GET':
        async with session.get(url, **kwargs) as r:
            r = await r.json()
    else:
        async with session.post(url, **kwargs) as r:
            r = await r.json()

    if r.get('status') is not None:
        raise codes.get(B2Error(r['status'], r['code']))(r['message'])

    return r


async def authorise_account(
        conn_info: B2ConnectionInfo,
        session: ClientSession
) -> AuthorisedAccount:
    """
    Used to log in to the B2 API.

    ...

    Parameters
    ----------
    conn_info: B2ConnectionInfo
        The app_id and key_id for the HTTP request headers
    session: ClientSession
        The ClientSession to send the HTTP requests with
    Returns
    ---------
    Tuple[str, str]
        Returns an authorization token that can be used for account-level operations,
        and a URL that should be used as the base URL for subsequent API calls.
    """
    id_and_key = f'{conn_info.key_id}:{conn_info.app_id}'.encode()
    basic_auth_string = 'Basic ' + base64.b64encode(id_and_key).decode()
    headers = {'Authorization': basic_auth_string}

    r = await http(
        'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
        session=session,
        method='GET',
        headers=headers
    )

    return AuthorisedAccount.from_response(r)


async def get_upload_url(
        conn_info: B2ConnectionInfo,
        bucket_id: str,
        session: ClientSession
) -> UploadUrl:
    """
    Gets an upload URL for uploading any files to a specified bucket.

    ...

    Parameters
    -----------
    conn_info: B2ConnectionInfo
        The key_id and the app_id for the account authorisation
    bucket_id: str
        The ID of the bucket to get the upload URL for.
    session: ClientSession
        The ClientSession to send the HTTP requests with.
    Returns
    ---------
    Tuple[str, str]
        Returns a URL that should be used for uploading files, and a token
        to be used as the authorisation for API calls to that URL.
    """
    account = await authorise_account(conn_info, session)

    r = await http(
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
        session: ClientSession,
        bucket_id: str,
        conn_info: B2ConnectionInfo
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
    conn_info: B2ConnectionInfo
        The key_id and the app_id for the account authorisation
    Returns
    ---------
    dict
        Returns a JSON response with data on the upload, and it's status, for more info:
        https://www.backblaze.com/b2/docs/b2_upload_file.html
    """
    upload_url = await get_upload_url(conn_info, bucket_id, session)

    headers = {
        'Authorization': upload_url.authorisation_token,
        'X-Bz-File-Name': str(file_name),
        'Content-Type': content_type,
        'X-Bz-Content-Sha1': hashlib.sha1(content_bytes).hexdigest()
    }
    r = await http(str(upload_url), session=session, method='POST', headers=headers, data=content_bytes)

    return File.from_response(r)


async def delete_file(
        file_name: str,
        file_id: str,
        session: ClientSession,
        conn_info: B2ConnectionInfo
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
        The ClientSession to send the HTTP requests with
    conn_info: B2ConnectionInfo
        The token obtained through authorise_account as authorisation for
        the API URL.
    Returns
    ---------
    dict
        Returns a JSON response with data on the file deletion, and it's status,
        for more info: https://www.backblaze.com/b2/docs/b2_delete_file_version.html
    """
    account = await authorise_account(conn_info, session)

    r = await http(
        f'{account.api_url}/b2api/v2/b2_delete_file_version',
        session=session,
        method='GET',
        params={'fileName': file_name, 'fileId': file_id},
        headers={'Authorization': account.authorisation_token}
    )

    return DeletedFile.from_response(r)
