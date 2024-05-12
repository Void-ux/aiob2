import datetime
import logging
from typing import Optional, Literal, Dict, List, Any

import aiohttp

from .models import (
    File,
    DeletedFile,
    DownloadedFile
)
from .http import HTTPClient
from .file import LargeFile
from .utils import setup_logging, MISSING

__all__ = ('Client', )


class Client:
    """Represents an aiob2 Client that makes requests to Backblaze's B2 API.

    Parameters
    ----------
    application_key_id: :class:`str`
        The application key id to use for authentication.
    application_key: :class:`str`
        The application key to use for authentication.
    session: Optional[:class:`aiohttp.ClientSession`]
        An optional session to pass, otherwise one will be lazily created.
    logging_handler: Optional[:class:`logging.LogHandler`]
        The log handler to use for the library's logger. If this is ``None``
        then the library will not set up anything logging related. Logging
        will still work if ``None`` is passed, though it is your responsibility
        to set it up.

        The default log handler if not provided is :class:`logging.StreamHandler`.
    log_formatter: :class:`logging.Formatter`
        The formatter to use with the given log handler. If not provided then it
        defaults to a colour based logging formatter (if available).
    log_level: :class:`int`
        The default log level for the library's logger. This is only applied if the
        ``log_handler`` parameter is not ``None``. Defaults to ``logging.INFO``.
    root_logger: :class:`bool`
        Whether to set up the root logger rather than the library logger.
        By default, only the library logger (``'aiob2'``) is set up. If this
        is set to ``True`` then the root logger is set up as well.

        Defaults to ``False``.
    """
    def __init__(
        self,
        application_key_id: str,
        application_key: str,
        *,
        session: Optional[aiohttp.ClientSession] = None,
        log_handler: Optional[logging.Handler] = MISSING,
        log_formatter: logging.Formatter = MISSING,
        log_level: int = MISSING,
        root_logger: bool = False
    ):
        self._http = HTTPClient(application_key_id, application_key, session)
        if log_handler is not None:
            setup_logging(
                handler=log_handler,
                formatter=log_formatter,
                level=log_level,
                root=root_logger
            )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.close()

    async def close(self):
        # This is really only possible if a Client is instantiated and no request is ever made
        if isinstance(self._http._session, aiohttp.ClientSession):  # type: ignore
            await self._http._session.close()  # type: ignore

    # TODO add all possible options; overload for customer encryption?
    async def upload_file(
        self,
        *,
        file_name: str,
        content_bytes: bytes,
        bucket_id: str,
        content_type: Optional[str] = None,
        content_disposition: Optional[str] = None,
        content_language: Optional[List[str]] = None,
        expires: Optional[datetime.datetime] = None,
        content_encoding: Optional[List[Literal['gzip', 'compress', 'deflate', 'identity']]] = None,
        comments: Optional[Dict[str, str]] = None,
        upload_timestamp: Optional[datetime.datetime] = None,
        server_side_encryption: Optional[Literal['AES256']] = None
    ) -> File:
        """Uploads a file to a bucket.

        Parameters
        -----------
        file_name: :class:`str`
            The name of the file.
        content_bytes: :class:`bytes`
            The raw bytes of the file to be uploaded.
        bucket_id: :class:`str`
            The ID of the bucket to upload to.
        content_type: Optional[:class:`str`]
            The content type of the content_bytes, e.g. video/mp4. This should be the original media/content,
            and not the result of the encodings applied. This is specified in the ``content_encoding``.

            B2's list of content types/extensions can be found [here](https://www.backblaze.com/b2/docs/content-types.html)

            If not provided, it will be automatically detected by Backblaze, and upon it not being discoverable, it'll
            default to ``application/octet-stream``.
        content_disposition: Optional[:class:`str`]
            Indicates whether the content is displayed inline in the browser, or as an attachment, which is
            locally downloaded.

            More info: [MDN Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition)
        content_language: Optional[List[:class:`str`]]
            The intended language(s) for the audience. By default, when this is not specified, it indicates
            that the content is for all language audiences.

            For example, ``['en']`` (English) or ``['en', 'da']`` (English and Danish).
        expires: Optional[:class:`datetime.datetime`]
            Indicates the date/time after which the content is considered expired. This does NOT automatically delete the
            file.
        content_encoding: Optional[List[Literal[``gzip``, ``compress``, ``deflate``, ``identity``]]]
            Lists any encodings that have been applied to the content, and in what order.
        comments: Optional[Dict[:class:`str`, :class:`str`]]
            A key-value pair of strings denoting any extra information to store as metadata with the file.
            The key will be ``quote_plus`` encoded.
        upload_timestamp: Optional[datetime.datetime]
            The upload timestamp to use, instead of now.

            .. note ::
                Your account must be authorized to use this by Backblaze support.
        server_side_encryption: Optional[Literal[`AES256`]]
            Specifying this will encrypt the data before storing it using
            [Server-Side Encryption with Backblaze-Managed Keys](https://backblaze.com/b2/docs/server_side_encryption.html)
            with the specified algorithm, currently only ``AES256``.

        Returns
        ---------
        :class:`File`
            The uploaded file.
        """

        data = await self._http.upload_file(
            content_bytes=content_bytes,
            content_type=content_type or 'b2/x-auto',
            file_name=file_name,
            bucket_id=bucket_id,
            content_disposition=content_disposition,
            content_language=content_language,
            expires=expires,
            content_encoding=content_encoding,
            comments=comments,
            upload_timestamp=upload_timestamp,
            server_side_encryption=server_side_encryption
        )
        return File(data)

    async def upload_large_file(
        self,
        bucket_id: str,
        file_name: str,
        content_type: Optional[str] = None,
        upload_timestamp: Optional[datetime.datetime] = None,
        comments: Optional[Dict[Any, Any]] = None
    ) -> LargeFile:
        """Creates a large file to upload parts/chunks to incrementally.

        Parameters
        ----------
        bucket_id: str
            The ID of the bucket to upload to.
        file_name: str
            The name of the remote file.
        content_type: str
            The content type of the file once every part is combined together.

            If not provided, it will be automatically detected by Backblaze, and upon it not being discoverable, it'll
            default to ``application/octet-stream``.
        upload_timestamp: Optional[datetime.datetime]
            The upload timestamp to use, instead of now.

            .. note ::
                Your account must be authorized to use this by Backblaze support.
        comments: Optional[Dict[Any, Any]]
            Key-value pairs denoting any extra information to store as metadata with the file.

            Unlike ``upload_file``, multiple k-v pairs may be provided of any JSON-compatible data type.
        """

        data = await self._http.start_large_file(
            bucket_id=bucket_id,
            file_name=file_name,
            content_type=content_type or 'b2/x-auto',
            upload_timestamp=upload_timestamp,
            comments=comments
        )
        return LargeFile(data, self._http)

    async def delete_file(
        self,
        file_name: str,
        file_id: str
    ) -> DeletedFile:
        """Deletes a file from a bucket.

        Parameters
        -----------
        file_name: :class:`str`
            The name of the file to delete.
        file_id: :class:`str`
            The id of the file to delete.

        Returns
        ---------
        :class:`DeletedFile`
            The deleted file.
        """

        data = await self._http.delete_file(file_name=file_name, file_id=file_id)
        return DeletedFile(data)

    async def download_file_by_id(
        self,
        file_id: str,
        *,
        range_: Optional[str] = None,
        content_disposition: Optional[str] = None,
        content_language: Optional[str] = None,
        expires: Optional[str] = None,
        cache_control: Optional[str] = None,
        content_encoding: Optional[str] = None,
        content_type: Optional[str] = None,
        server_side_encryption: Optional[str] = None
    ) -> DownloadedFile:
        """Downloads a file.

        Parameters
        -----------
        file_id: :class:`str`
            The file id of the file to be downloaded.
        range_: Optional[:class:`str`]
            A standard byte-range request, which will return just part of the stored file. For
            example, "bytes=0,99" selects bytes 0 through 99 (inclusive) of the file, so it will
            return the first 100 bytes.
        content_disposition: Optional[:class:`str`]
            Overrides the current 'b2-content-disposition' specified when the file was uploaded.
        content_language: Optional[:class:`str`]
            Overrides the current 'b2-content-language' specified when the file was uploaded.
        expires: Optional[:class:`str`]
            Overrides the current 'b2-expires' specified when the file was uploaded.
        cache_control: Optional[:class:`str`]
            Overrides the current 'b2-cache-control' specified when the file was uploaded.
        content_encoding: Optional[:class:`str`]
            Overrides the current 'b2-content-encoding' specified when the file was uploaded.
        content_type: Optional[:class:`str`]
            Overrides the current 'Content-Type' specified when the file was uploaded.
        server_side_encryption: Optional[:class:`str`]
            This is requires if the file was uploaded and stored using Server-Side Encryption with
            Customer-Managed Keyts (SSE-C)

        Returns
        ---------
        :class:`DownloadedFile`
            The file requested.
        """

        data = await self._http.download_file_by_id(
            file_id=file_id,
            range_=range_,
            content_disposition=content_disposition,
            content_language=content_language,
            expires=expires,
            cache_control=cache_control,
            content_encoding=content_encoding,
            content_type=content_type,
            server_side_encryption=server_side_encryption
        )
        return DownloadedFile(data[0], data[1])  # type: ignore

    async def download_file_by_name(
        self,
        file_name: str,
        bucket_name: str,
        *,
        range_: Optional[str] = None,
        content_disposition: Optional[str] = None,
        content_language: Optional[str] = None,
        expires: Optional[str] = None,
        cache_control: Optional[str] = None,
        content_encoding: Optional[str] = None,
        content_type: Optional[str] = None,
        server_side_encryption: Optional[str] = None
    ) -> DownloadedFile:
        """Downloads a file.

        Parameters
        -----------
        file_name: :class:`str`
            The file name of the file to be downloaded.
        bucket_name: :class:`str`
            The bucket name of the file to be downloaded. This should only be specified if you have specified
            file_name and not file_id.
        range_: Optional[:class:`str`]
            A standard byte-range request, which will return just part of the stored file. For
            example, "bytes=0,99" selects bytes 0 through 99 (inclusive) of the file, so it will
            return the first 100 bytes.
        content_disposition: Optional[:class:`str`]
            Overrides the current 'b2-content-disposition' specified when the file was uploaded.
        content_language: Optional[:class:`str`]
            Overrides the current 'b2-content-language' specified when the file was uploaded.
        expires: Optional[:class:`str`]
            Overrides the current 'b2-expires' specified when the file was uploaded.
        cache_control: Optional[:class:`str`]
            Overrides the current 'b2-cache-control' specified when the file was uploaded.
        content_encoding: Optional[:class:`str`]
            Overrides the current 'b2-content-encoding' specified when the file was uploaded.
        content_type: Optional[:class:`str`]
            Overrides the current 'Content-Type' specified when the file was uploaded.
        server_side_encryption: Optional[:class:`str`]
            This is requires if the file was uploaded and stored using Server-Side Encryption with
            Customer-Managed Keyts (SSE-C)

        Returns
        ---------
        :class:`DownloadedFile`
            The file requested.
        """

        data = await self._http.download_file_by_name(
            file_name=file_name,
            bucket_name=bucket_name,
            range_=range_,
            content_disposition=content_disposition,
            content_language=content_language,
            expires=expires,
            cache_control=cache_control,
            content_encoding=content_encoding,
            content_type=content_type,
            server_side_encryption=server_side_encryption
        )
        return DownloadedFile(data[0], data[1])  # type: ignore
