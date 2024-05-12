from __future__ import annotations

import datetime
import hashlib
from typing import IO, Generator, Union, Optional, Literal, Dict, List, Any

from .utils import format_timestamp
from .http import HTTPClient, UploadPayload
from .models.file import LargeFilePart, PartialFile, File



class LargeFile(PartialFile):
    """Represents a large file being uploaded to Backblaze.

    Attributes
    ----------
    account_id: :class:`str`
        The account's ID that owns the file.
    action: Literal[``'start'``]
        This will always be ``start``.
    bucket_id: :class:`str`
        The file's bucket ID.
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
    parts: List[:class:`LargeFilePart`]
        A list of all the uploaded file parts.
    """
    def __init__(
        self,
        data: UploadPayload,
        http: HTTPClient
    ):
        super().__init__(data)

        # appease type checker
        assert data['contentType'] is not None
        assert data['fileId'] is not None

        self.account_id: str = data['accountId']
        self.action: Literal['upload'] = data['action']  # type: ignore
        self.bucket_id: str = data['bucketId']
        self.content_type: str = data['contentType']
        self.info: Dict[Any, Any] = data['fileInfo']
        self.retention: Optional[Dict[Any, Any]] = data.get('fileRetention')
        self.legal_hold: Optional[Dict[Any, Any]] = data.get('legalHold')
        self.replication_status: Optional[Literal['PENDING', 'COMPLETED', 'FAILED', 'REPLICA']] = data.get('replicationStatus')  # noqa
        self.server_side_encryption: Optional[Dict[Any, Any]] = data.get('serverSideEncryption')
        self.created: datetime.datetime = format_timestamp(data['uploadTimestamp'])

        self._http = http
        self._cancelled = False
        self._finished = False
        self._parts: List[LargeFilePart] = []
        self._sha1_checksums: List[str] = []

        self.recommended_part_size: int = self._http._recommended_part_size  # type: ignore
        self.absolute_minimum_part_size: int = self._http._absolute_minimum_part_size  # type: ignore

    async def chunk_file(self, file: Union[str, IO[bytes]]) -> None:
        """|coro|
        
        Automatically chunks a file or buffer into optimal sizes for the fastest upload.

        Parameters
        ----------
        file: Union[:class:`str`, IO[T]]
            The file to upload.        
        """
        if self._cancelled:
            raise RuntimeError('New parts cannot be uploaded to a cancelled large file upload')
        if self._finished:
            raise RuntimeError('New parts cannot be uploaded to an already complete large file')

        if isinstance(file, str):
            file = open(file, 'rb')

        try:
            def _chunk(size: int) -> Generator[bytes, None, None]:
                nonlocal file
                while True:
                    data = file.read(size)
                    if data:
                        break
                    yield data

            for chunk in _chunk(self.recommended_part_size):
                await self.upload_part(chunk)
        finally:
            file.close()

    async def upload_part(self, content_bytes: bytes) -> LargeFilePart:
        """|coro|

        Uploads a part of the large file.

        Large file parts must be above the ``self.absolute_minimum_part_size``. It's recommended to adhere to the
        ``recommended_part_size`` for the fastest possible upload times.

        Parameters
        ----------
        content_bytes: :class:`bytes`
            The raw bytes of the file part.
        """
        if self._cancelled:
            raise RuntimeError('New parts cannot be uploaded to a cancelled large file upload')
        if self._finished:
            raise RuntimeError('New parts cannot be uploaded to an already complete large file')

        # we could use the Backblaze-sent sha1s instead of storing our own,
        # but this'd defeat the purpose of the final double-check
        sha1 = hashlib.sha1(content_bytes).hexdigest()

        part = await self._http.upload_part(
            self.id,
            len(self._parts) + 1,
            content_bytes,
            sha1
        )
        part = LargeFilePart(part)
        self._parts.append(part)
        self._sha1_checksums.append(sha1)

        return part

    async def finish(self) -> File:
        """|coro|

        Combines every uploaded part into a single file.
        """
        if self._cancelled:
            raise RuntimeError('Cancelled large files cannot be completed')
        if self._finished:
            raise RuntimeError('This large file has already been finished')
        if len(self._parts) <= 1:
            raise RuntimeError('Large files must have at least 2 parts to be finished')

        data = await self._http.finish_large_file(self.id, [i.content_sha1 for i in self._parts])
        return File(data)

    async def cancel(self) -> None:
        """|coro|

        Cancels the upload of a large file, and deletes all of the parts that have been uploaded.
        """
        if self._cancelled:
            raise RuntimeError('This large file upload has already been cancelled')
        if self._finished:
            raise RuntimeError('This large file has already been combined into a single file, it can now only be deleted')

        await self._http.cancel_large_file(self.id)
        self._cancelled = True
