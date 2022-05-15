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
