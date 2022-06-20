import datetime
from typing import NamedTuple


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
        return f"<File {' '.join([f'{key}={value}' for key, value in zip(self._asdict(), self)])}>"

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


class DownloadAuthorisation(NamedTuple):
    authorisation_token: str
    bucket_id: str
    file_name_prefix: str

    @classmethod
    def from_response(cls, response: dict):
        return cls(
            authorisation_token=response['authorizationToken'],
            bucket_id=response['bucketId'],
            file_name_prefix=response['fileNamePrefix']
        )

    def __eq__(self, other):
        if isinstance(other, DownloadAuthorisation):
            return self.authorisation_token == other.authorisation_token and \
                   self.bucket_id == other.bucket_id and \
                   self.file_name_prefix == other.file_name_prefix

        return False

    def __repr__(self):
        return f'<DownloadAuthorisation authorisation_token={self.authorisation_token} bucket_id={self.bucket_id} ' \
               f'file_name_prefix={self.file_name_prefix}>'


class DownloadedFile(NamedTuple):
    file_name: str
    file_id: str
    content_sha1: str
    upload_timestamp: datetime.datetime
    accept_ranges: str
    content: bytes
    content_type: str
    content_length: str
    date: str

    @classmethod
    def from_response(cls, data: bytes, response: dict):
        timestamp = float(response['X-Bz-Upload-Timestamp'])
        timestamp /= 1000.

        return cls(
            file_name=response['x-bz-file-name'],
            file_id=response['x-bz-file-id'],
            content_sha1=response['x-bz-content-sha1'],
            upload_timestamp=datetime.datetime.utcfromtimestamp(timestamp),
            accept_ranges=response['Accept-Ranges'],
            content=data,
            content_type=response['Content-Type'],
            content_length=response['Content-Length'],
            date=response['Date']
        )

    def __eq__(self, other):
        if isinstance(other, DownloadedFile):
            return self.file_id == other.file_id

        return False

    def __repr__(self):
        return f"<DownloadedFile {' '.join([f'{key}={value}' for key, value in zip(self._asdict(), self)])}>"
