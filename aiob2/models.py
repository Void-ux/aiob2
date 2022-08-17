import datetime
from typing import NamedTuple, Any
from pydantic import BaseModel as PydanticBaseModel, Extra


class B2ConnectionInfo(NamedTuple):
    key_id: str
    app_id: str


class B2AuthInfo(NamedTuple):
    url: str
    auth_token: str


class BaseModel(PydanticBaseModel):
    class Config:
        allow_mutation = False
        extra = Extra.forbid


class File(BaseModel):
    account_id: str
    action: str
    bucket_id: str
    content_length: int
    content_sha1: str
    content_md5: str
    content_type: str
    id: str
    info: dict
    name: str
    retention: dict
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
            id=response['fileId'],
            info=response['fileInfo'],
            name=response['fileName'],
            retention=response['fileRetention'],
            legal_hold=response['legalHold'],
            server_side_encryption=response['serverSideEncryption'],
            upload_timestamp=datetime.datetime.utcfromtimestamp(timestamp)
        )

    def __repr__(self):
        return f"<File {str(self)}>"

    def __eq__(self, other):
        if isinstance(other, File):
            return self.id == other.id

        return False


class AuthorisedAccount(BaseModel):
    account_id: str
    authorisation_token: str
    allowed: dict[str, Any]
    api_url: str
    download_url: str
    recommended_part_size: int
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
        return f"<AuthorisedAccount {str(self)}>"

    def __eq__(self, other):
        if isinstance(other, AuthorisedAccount):
            return self.account_id == other.account_id

        return False


class UploadData(BaseModel):
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


class DeletedFile(BaseModel):
    name: str
    id: str

    @classmethod
    def from_response(cls, response: dict):
        return cls(
            name=response['fileName'],
            id=response['fileId']
        )

    def __eq__(self, other):
        if isinstance(other, DeletedFile) or isinstance(other, File):
            return self.id == other.id

        return False

    def __repr__(self):
        return f'<DeletedFile {str(self)}>'


class DownloadAuthorisation(BaseModel):
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
        return f'<DownloadAuthorisation {str(self)}>'


class DownloadedFile(BaseModel):
    name: str
    id: str
    content_sha1: str
    upload_timestamp: datetime.datetime
    accept_ranges: str
    content: bytes
    content_type: str
    content_length: str
    download_date: str

    @classmethod
    def from_response(cls, data: bytes, response: dict):
        timestamp = float(response['X-Bz-Upload-Timestamp'])
        timestamp /= 1000.

        return cls(
            name=response['x-bz-file-name'],
            id=response['x-bz-file-id'],
            content_sha1=response['x-bz-content-sha1'],
            upload_timestamp=datetime.datetime.utcfromtimestamp(timestamp),
            accept_ranges=response['Accept-Ranges'],
            content=data,
            content_type=response['Content-Type'],
            content_length=response['Content-Length'],
            download_date=response['Date']
        )

    def __eq__(self, other):
        if isinstance(other, DownloadedFile):
            return self.id == other.id

        return False

    def __repr__(self):
        return f"<DownloadedFile {str(self)}>"
