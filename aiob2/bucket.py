import base64
import hashlib
import datetime

from typing import NamedTuple
from aiohttp import ClientSession, ClientResponse
from .exceptions import codes, B2Error


class B2ConnectionInfo(NamedTuple):
    key_id: str
    app_id: str


class B2AuthInfo(NamedTuple):
    url: str
    auth_token: str


class File(NamedTuple):
    account_id: str
    action: str
    bucket_id: str
    content_length: int
    content_sha1: str
    content_md5: str
    content_type: str
    file_id: str
    file_info: dict
    file_name: str
    file_retention: dict
    legal_hold: dict
    server_side_encryption: dict
    upload_timestamp: datetime.datetime

    @classmethod
    def from_response(cls, response: dict):
        """Constructs a file object from an upload_file's return value."""
        timestamp = float(response['uploadTimestamp'])
        timestamp /= 1000.

        return cls(
            account_id=response['accountId'],
            action=response['action'],
            bucket_id=response['bucketId'],
            content_length=response['contentLength'],
            content_sha1=response['contentSha1'],
            content_md5=response['contentMd5'],
            content_type=response['contentType'],
            file_id=response['fileId'],
            file_info=response['fileInfo'],
            file_name=response['fileName'],
            file_retention=response['fileRetention'],
            legal_hold=response['legalHold'],
            server_side_encryption=response['serverSideEncryption'],
            upload_timestamp=datetime.datetime.utcfromtimestamp(timestamp)
        )

    def __repr__(self):
        return f"<File {' '.join([f'{key}={value}' for key, value in zip(self, self._asdict())])}>"

    def __eq__(self, other):
        if isinstance(other, File):
            return self.file_id == other.file_id

        return False


class AuthorisedAccount(NamedTuple):
    account_id: int
    authorisation_token: str
    allowed: dict
    api_url: str
    download_url: str
    recommended_part_size: str
    absolute_minimum_part_size: int
    s3_api_url: str

    @classmethod
    def from_response(cls, response: dict):
        return cls(
            account_id=response['accountId'],
            authorisation_token=response['authorizationToken'],
            allowed=response['allowed'],
            api_url=response['apiUrl'],
            download_url=response['downloadUrl'],
            recommended_part_size=response['recommendedPartSize'],
            absolute_minimum_part_size=response['absoluteMinimumPartSize'],
            s3_api_url=response['s3ApiUrl']
        )

    def __repr__(self):
        return f"<AuthorisedAccount {' '.join([f'{key}={value}' for key, value in zip(self._asdict(), self)])}>"

    def __eq__(self, other):
        if isinstance(other, AuthorisedAccount):
            return self.account_id == other.account_id

        return False


class UploadUrl(NamedTuple):
    bucket_id: str
    upload_url: str
    authorisation_token: str

    @classmethod
    def from_response(cls, response: dict):
        return cls(
            bucket_id=response['bucketId'],
            upload_url=response['uploadUrl'],
            authorisation_token=response['authorizationToken']
        )

    def __eq__(self, other):
        if isinstance(other, AuthorisedAccount):
            return not any(i != x for i, x in zip(self, other))

        return False

    def __repr__(self):
        return self.upload_url


class DeletedFile(NamedTuple):
    file_name: str
    file_id: str

    @classmethod
    def from_response(cls, response: dict):
        return cls(
            file_name=response['fileName'],
            file_id=response['fileId']
        )

    def __eq__(self, other):
        if isinstance(other, DeletedFile):
            return self.file_id == other.file_id

        return False

    def __repr__(self):
        return f'<DeletedFile file_name={self.file_name} file_id={self.file_id}>'


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

    async with session.get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account", headers=headers) as r:
        r = await r.json()

    if r.get('status') is not None:
        raise codes.get(B2Error(r['status'], r['code']))(r['message'])

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
    headers = {'Authorization': account.authorisation_token}
    async with session.get(f"{account.api_url}/b2api/v2/b2_get_upload_url",
                           params={'bucketId': bucket_id},
                           headers=headers) as r:
        r = await r.json()

    if r.get('status') is not None:
        raise codes.get(B2Error(r['status'], r['code']))(r['message'])

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
    async with session.post(str(upload_url), data=content_bytes, headers=headers) as r:
        r = await r.json()

    if r.get('status') is not None:
        raise codes.get(B2Error(r['status'], r['code']))(r['message'])

    return File.from_response(r)


async def delete_file(
        file_name: str,
        file_id: str,
        session: ClientSession,
        conn_info: B2ConnectionInfo
) -> ClientResponse:
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

    async with session.get(f'{account.api_url}/b2api/v2/b2_delete_file_version',
                           params={'fileName': file_name, 'fileId': file_id},
                           headers={'Authorization': account.authorisation_token}) as r:
        r = await r.json()

    if r.get('status') is not None:
        raise codes.get(B2Error(r['status'], r['code']))(r['message'])

    return DeletedFile.from_response(r)  # type: ignore
