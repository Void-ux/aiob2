import datetime
from typing import TypedDict, Literal, Optional, Union
from typing_extensions import NotRequired

from .archetypes import B2Object
from ..utils import format_timestamp

__all__ = ('File', 'DeletedFile', 'DownloadedFile')


class PartialFilePayload(TypedDict):
    fileName: str
    fileId: Optional[str]


class UploadPayload(PartialFilePayload):
    accountId: str
    action: Literal['start', 'upload', 'hide', 'folder']
    bucketId: str
    contentLength: Optional[int]
    contentSha1: Optional[str]
    contentMd5: NotRequired[Optional[str]]
    contentType: Optional[str]
    fileInfo: dict
    fileRetention: NotRequired[Optional[dict]]
    legalHold: NotRequired[dict]
    replicationStatus: NotRequired[Literal['PENDING', 'COMPLETED', 'FAILED', 'REPLICA']]
    serverSideEncryption: NotRequired[Optional[dict]]
    uploadTimestamp: Union[int, Literal[0]]


DownloadPayloadHeaders = TypedDict('DownloadPayloadHeaders', {
    'Content-Length': int,
    'Content-Type': str,
    'X-Bz-File-Id': str,
    'X-Bz-File-Name': str,
    'X-Bz-Content-Sha1': str,
    'X-Bz-Upload-Timestamp': str,
    'Accept-Ranges': str,
    'Date': str
})


class PartialFile(B2Object):
    def __init__(
        self,
        data: PartialFilePayload
    ):
        # appease type checker
        assert data['fileId'] is not None

        self.name: str = data['fileName']
        self.id: str = data['fileId']

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, File):
            return self.id == other.id

        return False


class File(PartialFile):
    def __init__(
        self,
        data: UploadPayload
    ):
        super().__init__(data)

        # appease type checker
        assert data['contentLength'] is not None
        assert data['contentSha1'] is not None
        assert data['contentType'] is not None

        self.account_id: str = data['accountId']
        self.action: str = data['action']
        self.bucket_id: str = data['bucketId']
        self.content_length: int = data['contentLength']
        self.content_sha1: str = data['contentSha1']
        self.content_md5: Optional[str] = data.get('contentMd5')
        self.content_type: str = data['contentType']
        self.info: dict = data['fileInfo']
        self.retention: Optional[dict] = data.get('fileRetention')
        self.legal_hold: Optional[dict] = data.get('legalHold')
        self.replication_status: Optional[str] = data.get('replicationStatus')
        self.server_side_encryption: Optional[dict] = data.get('serverSideEncryption')
        self.upload_timestamp: datetime.datetime = format_timestamp(data['uploadTimestamp'])


class DeletedFile(PartialFile):
    def __init__(
        self,
        data: PartialFilePayload
    ):
        super().__init__(data)


class DownloadedFile(B2Object):
    def __init__(
        self,
        content: bytes,
        headers: DownloadPayloadHeaders
    ):
        self.content_length: int = headers['Content-Length']
        self.content_type: str = headers['Content-Type']
        self.id: str = headers['X-Bz-File-Id']
        self.name: str = headers['X-Bz-File-Name']
        self.content_sha1: str = headers['X-Bz-Content-Sha1']
        self.upload_timestamp: datetime.datetime = format_timestamp(int(headers['X-Bz-Upload-Timestamp']))
        self.date: datetime.datetime = datetime.datetime.strptime(
            headers['Date'],
            '%a, %d %b %Y %H:%M:%S %Z'
        )
        self.content: bytes = content
