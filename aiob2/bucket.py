import hashlib

from typing import Optional

from .types import *
from .http import HTTPClient

__all__ = ['Client']


class Client:
    def __init__(self, connection_info: B2ConnectionInfo):
        self.connection_info = connection_info
        self._http = HTTPClient(connection_info)

    async def close(self):
        await self._http.session.close()

    async def upload_file(
            self,
            *,
            content_bytes: bytes,
            content_type: str,
            file_name: str,
            bucket_id: str
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
        bucket_id: str
            The ID of the bucket to upload to.
        Returns
        ---------
        File
            A File object wrapping the data provided by Backblaze.
        """
        upload_url = await self._http.get_upload_url(bucket_id)

        headers = {
            'Authorization': upload_url.authorisation_token,
            'X-Bz-File-Name': str(file_name),
            'Content-Type': content_type,
            'X-Bz-Content-Sha1': hashlib.sha1(content_bytes).hexdigest()
        }
        r = await self._http.request(str(upload_url), method='POST', headers=headers, data=content_bytes)

        return File.from_response(r)

    async def delete_file(
            self,
            file_name: str,
            file_id: str
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
        Returns
        ---------
        DeletedFile
            Returns a DeletedFile object with the attributes `file_name` and `file_id`.
        """
        account = await self._http.authorise_account()

        r = await self._http.request(
            f'{account.api_url}/b2api/v2/b2_delete_file_version',
            method='GET',
            params={'fileName': file_name, 'fileId': file_id},
            headers={'Authorization': account.authorisation_token}
        )

        return DeletedFile.from_response(r)

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
        """
        Downloads a file.

        ...

        Parameters
        -----------
            file_id: str
                The file id of the file to be downloaded.
            content_disposition: Optional[str]
                Overrides the current 'b2-content-disposition' specified when the file was uploaded.
            content_language: Optional[str]
                Overrides the current 'b2-content-language' specified when the file was uploaded.
            expires: Optional[str]
                Overrides the current 'b2-expires' specified when the file was uploaded.
            cache_control: Optional[str]
                Overrides the current 'b2-cache-control' specified when the file was uploaded.
            content_encoding: Optional[str]
                Overrides the current 'b2-content-encoding' specified when the file was uploaded.
            content_type: Optional[str]
                Overrides the current 'Content-Type' specified when the file was uploaded.
            server_side_encryption: Optional[str]
                This is requires if the file was uploaded and stored using Server-Side Encryption with
                Customer-Managed Keys (SSE-C)
        Returns
        ---------
        DownloadedFile
            A DownloadedFile object containing the data Backblaze sent.
        """
        account = await self._http.authorise_account()

        headers = {
            'Authorization': account.authorisation_token,
            'b2ContentDisposition': content_disposition,
            'b2ContentLanguage': content_language,
            'b2Expires': expires,
            'b2CacheControl': cache_control,
            'b2ContentEncoding': content_encoding,
            'b2ContentType': content_type,
            'serverSideEncryption': server_side_encryption
        }
        headers = {key: value for key, value in headers.items() if value is not None}

        data = await self._http.request(
            f'{account.download_url}/b2api/v2/b2_download_file_by_id',
            method='GET',
            headers=headers,
            params={'fileId': file_id}
        )
        return DownloadedFile.from_response(data[1], data[0])

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
        """
        Downloads a file.

        ...

        Parameters
        -----------
            file_name: Optional[str]
                The file name of the file to be downloaded.
            bucket_name: Optional[str]
                The bucket name of the file to be downloaded. This should only be specified if you have specified
                file_name and not file_id.
            content_disposition: Optional[str]
                Overrides the current 'b2-content-disposition' specified when the file was uploaded.
            content_language: Optional[str]
                Overrides the current 'b2-content-language' specified when the file was uploaded.
            expires: Optional[str]
                Overrides the current 'b2-expires' specified when the file was uploaded.
            cache_control: Optional[str]
                Overrides the current 'b2-cache-control' specified when the file was uploaded.
            content_encoding: Optional[str]
                Overrides the current 'b2-content-encoding' specified when the file was uploaded.
            content_type: Optional[str]
                Overrides the current 'Content-Type' specified when the file was uploaded.
            server_side_encryption: Optional[str]
                This is requires if the file was uploaded and stored using Server-Side Encryption with
                Customer-Managed Keys (SSE-C)
        Returns
        ---------
        DownloadedFile
            A DownloadedFile object containing the data Backblaze sent.
        """

        account = await self._http.authorise_account()

        headers = {
            'Authorization': account.authorisation_token,
            'b2ContentDisposition': content_disposition,
            'b2ContentLanguage': content_language,
            'b2Expires': expires,
            'b2CacheControl': cache_control,
            'b2ContentEncoding': content_encoding,
            'b2ContentType': content_type,
            'serverSideEncryption': server_side_encryption
        }
        headers = {key: value for key, value in headers.items() if value is not None}

        data = await self._http.request(
            f'{account.download_url}/file/{bucket_name}/{file_name}',
            method='GET',
            headers=headers,
        )

        return DownloadedFile.from_response(data[1], data[0])
