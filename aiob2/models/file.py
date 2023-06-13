from __future__ import annotations

import datetime
from typing import TypedDict, Literal, Optional, Union, Dict, Any
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
    fileInfo: Dict[Any, Any]
    fileRetention: NotRequired[Optional[Dict[Any, Any]]]
    legalHold: NotRequired[Dict[Any, Any]]
    replicationStatus: NotRequired[Literal['PENDING', 'COMPLETED', 'FAILED', 'REPLICA']]
    serverSideEncryption: NotRequired[Optional[Dict[Any, Any]]]
    uploadTimestamp: Union[int, Literal[0]]


DownloadPayloadHeaders = TypedDict('DownloadPayloadHeaders', {
    'Content-Length': int,
    'Content-Type': str,
    'X-Bz-File-Id': str,
    'X-Bz-File-Name': str,
    'X-Bz-Content-Sha1': str,
    'X-Bz-Upload-Timestamp': str,
    'Accept-Ranges': str,
    'Date': str,
    'Content-Disposition': NotRequired[str],
    'Content-Language': NotRequired[str],
    'Expires': NotRequired[str],
    'Content-Encoding': NotRequired[str],
    'X-Bz-Server-Side-Encryption': NotRequired[Literal['AES256']]
})


class PartialFile(B2Object):
    """Represents a "partial" file from Backblaze.

    Attributes
    ----------
    name: :class:`str`
        The file's name.
    id: :class:`str`
        The file's ID.
    """
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

    def __eq__(self, other: Any):
        return isinstance(other, File) and self.id == other.id


class LargeFilePartPayload(TypedDict):
    fileId: str
    partNumber: int
    contentLength: int
    contentSha1: str
    contentMd5: Optional[str]
    serverSideEncryption: Optional[Dict[Any, Any]]
    uploadTimestamp: int


class LargeFilePart(B2Object):
    def __init__(self, payload: LargeFilePartPayload) -> None:
        self.file_id: str = payload['fileId']
        self.part_number: int = payload['partNumber']
        self.content_length: int = payload['contentLength']
        self.content_sha1: str = payload['contentSha1']
        self.content_md5: Optional[str] = payload['contentMd5']
        self.server_side_encryption: Optional[Dict[Any, Any]] = payload['serverSideEncryption']
        self.upload_timestamp: datetime.datetime = format_timestamp(payload['uploadTimestamp'])


class File(PartialFile):
    """Represents a file uploaded to Backblaze.

    Attributes
    ----------
    account_id: :class:`str`
        The account's ID that owns the file.
    action: Literal[``'upload'``]
        This will always be ``upload``.
    bucket_id: :class:`str`
        The file's bucket ID.
    content_length: :class:`int`
        The file's size represented in number of bytes.
    content_sha1: :class:`str`
        The file's SHA-1.
    content_md5: Optional[:class:`str`]
        The MD5 of the file's bytes as a 40-digit hex string.
    content_type: :class:`str`
        The file's content type, e.g. image/jpeg.
    id: :class:`str`
        The file's ID.
    info: :class:`dict`
        Any custom info regarding the file submitted at upload.
    name: :class:`str`
        The file's name.
    retention: Optional[:class:`dict`]
        The file's object lock retention settings.
    legal_hold: Optional[:class:`dict`]
        The file's object lock legal hold status.
    replication_status: Optional[Literal[``'PENDING'``, ``'COMPLETED'``, ``'FAILED'``, ``'REPLICA'``]
        The file's replication status.
    server_side_encryption: Optional[:class:`dict`]
        The file's encryption mode, and algorithm.
    created: :class:`datetime.datetime`
        The time at which the file was uploaded.
    """
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
        self.action: Literal['upload'] = data['action']  # type: ignore
        self.bucket_id: str = data['bucketId']
        self.content_length: int = data['contentLength']
        self.content_sha1: str = data['contentSha1']
        self.content_md5: Optional[str] = data.get('contentMd5')
        self.content_type: str = data['contentType']
        self.info: Dict[Any, Any] = data['fileInfo']
        self.retention: Optional[Dict[Any, Any]] = data.get('fileRetention')
        self.legal_hold: Optional[Dict[Any, Any]] = data.get('legalHold')
        self.replication_status: Optional[Literal['PENDING', 'COMPLETED', 'FAILED', 'REPLICA']] = data.get('replicationStatus')  # noqa
        self.server_side_encryption: Optional[Dict[Any, Any]] = data.get('serverSideEncryption')
        self.created: datetime.datetime = format_timestamp(data['uploadTimestamp'])


class DeletedFile(PartialFile):
    """Represents a deleted file from Backblaze.

    Attributes
    ----------
    name: :class:`str`
        The file's name.
    id: :class:`str`
        The file's ID.
    """
    def __init__(
        self,
        data: PartialFilePayload
    ):
        super().__init__(data)


class DownloadedFile(B2Object):
    """Represents a file downloaded from Backblaze.

    Attributes
    ----------
    name: :class:`str`
        The file's name.
    id: :class:`str`
        The file's ID.
    content_type: :class:`str`
        The file's content type, e.g. image/jpeg.
    content_length: :class:`int`
        The file's size represented in number of bytes.
    content_sha1: :class:`str`
        The file's SHA-1.
    created: :class:`datetime.datetime`
        The time at which the file was uploaded.
    downloaded_at: :class:`str`
        The date at which the download was requested.
    content_disposition: Optional[:class:`str`]
        Whether or not the content is intended to be played inline, or downloaded locally and optionally the filename.
    content_language: Optional[:class:`str`]
        The content's intended language audience.
    expires: Optional[:class:`datetime.datetime`]
        The intended expiration date of the content.
    content_encoding: Optional[:class:`str`]
        The content's encoding in the order they were performed in.
    server_side_encryption: Optional[Literal[``AES256``]]
        The server side encryption performed on the content including the algorithm.
    comments: Optional[Dict[:class:`str`, :class:`str`]]
        The comments uploaded with the file.
    content: :class:`bytes`
        The raw bytes of the downloaded file.
    """
    def __init__(
        self,
        content: bytes,
        headers_: DownloadPayloadHeaders
    ):
        headers: Dict[str, Any] = {k.lower(): v for k, v in headers_.items()}
        b2_info_headers = (
            'b2-content-disposition',
            'b2-content-language',
            'b2-expires',
            'b2-cache-control',
            'b2-content-encoding',
            'b2-content-type'
        )
        # comments are turned to lower case by Backblaze
        # so the above lowercasing won't impact anything
        comments: Dict[str, str] = {
            k[10:]: v for k, v in headers.items() if k.startswith('x-bz-info-') and not k.endswith(b2_info_headers)
        }

        self.content_length: int = headers['content-length']
        self.content_type: str = headers['content-type']
        self.id: str = headers['x-bz-file-id']
        self.name: str = headers['x-bz-file-name']
        self.content_sha1: str = headers['x-bz-content-sha1']
        self.created: datetime.datetime = format_timestamp(int(headers['x-bz-upload-timestamp']))
        self.downloaded_at: datetime.datetime = datetime.datetime.strptime(
            headers['date'],
            '%a, %d %b %Y %H:%M:%S %Z'
        )

        self.content_disposition: Optional[str] = headers.get('content-disposition')
        self.content_language: Optional[str] = headers.get('content-language')
        self.cache_control: Optional[str] = headers.get('cache-control')
        if (expires := headers.get('expires')) is not None:
            expires = datetime.datetime.strptime(expires, '%a, %d %b %Y %H:%M:%S %Z')
        else:
            expires = None
        self.expires: Optional[datetime.datetime] = expires
        self.content_encoding: Optional[str] = headers.get('content-encoding')
        self.server_side_encryption: Optional[Literal['AES256']] = headers.get('x-bz-server-side-encryption')
        self.comments: Optional[Dict[str, str]] = comments or None

        self.content: bytes = content
