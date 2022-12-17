from typing import Optional

import aiohttp

from .models import (
    File,
    DeletedFile,
    DownloadedFile
)
from .http import HTTPClient

__all__ = ('Client', )


class Client:
    def __init__(
        self,
        application_key_id: str,
        application_key: str,
        *,
        session: Optional[aiohttp.ClientSession] = None
    ):
        self._http = HTTPClient(application_key_id, application_key, session)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        # This is really only possible if a Client is instantiated and no request is ever made
        if isinstance(self._http._session, aiohttp.ClientSession):
            await self._http._session.close()

    async def upload_file(
        self,
        *,
        content_bytes: bytes,
        content_type: str,
        file_name: str,
        bucket_id: str
    ) -> File:
        """Uploads a file to a bucket.

        Parameters
        -----------
        content_bytes: :class:`bytes`
            The raw bytes of the file to be uploaded.
        content_type: :class:`str`
            The content type of the content_bytes, e.g. video/mp4.
        file_name: :class:`str`
            The name of the file.
        bucket_id: :class:`str`
            The ID of the bucket to upload to.

        Returns
        ---------
        :class:`File`
            The uploaded file.
        """

        data = await (await self._http.upload_file(
            content_bytes=content_bytes,
            content_type=content_type,
            file_name=file_name,
            bucket_id=bucket_id
        ))
        return File(data)

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
            content_disposition=content_disposition,
            content_language=content_language,
            expires=expires,
            cache_control=cache_control,
            content_encoding=content_encoding,
            content_type=content_type,
            server_side_encryption=server_side_encryption
        )
        return DownloadedFile(data[0], data[1])  # type: ignore
