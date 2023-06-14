import os
import pytest
import logging
from pathlib import Path

from aiob2 import Client, File
from .conftest import ValueStorage

path = Path(__file__).resolve().parent / 'payloads/test_image.jpg'


class TestDownload:
    @pytest.mark.asyncio
    @pytest.mark.order(2)
    async def test_download(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)
        file = ValueStorage.test_upload_file
        assert isinstance(file, File)

        downloaded_file = await client.download_file_by_name(file_name=file.name, bucket_name=os.environ['BUCKET_NAME'])

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert downloaded_file.content == path.read_bytes()
        assert downloaded_file.content_disposition == 'inline; filename="foo.jpg"'
        assert downloaded_file.content_language == 'en, ru'
        assert downloaded_file.comments == {'foo': 'bar'}
        assert downloaded_file.server_side_encryption == file.server_side_encryption['algorithm']  # type: ignore

        # Download (by id)

        downloaded_file = await client.download_file_by_id(file_id=file.id)

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert downloaded_file.content == path.read_bytes()

        await client.close()

    @pytest.mark.asyncio
    @pytest.mark.order(2)
    async def test_download_range(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)
        file = ValueStorage.test_upload_file
        assert isinstance(file, File)

        range_length = 100
        range_str = f"bytes=0-{range_length - 1}"

        downloaded_file = await client.download_file_by_name(
            file_name=file.name,
            bucket_name=os.environ['BUCKET_NAME'],
            range_=range_str
        )

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert len(downloaded_file.content) <= range_length
        assert int(downloaded_file.content_length) <= range_length
        assert int(downloaded_file.content_length) == len(downloaded_file.content)

        # Download (by id)

        downloaded_file = await client.download_file_by_id(file_id=file.id, range_=range_str)

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert len(downloaded_file.content) <= range_length
        assert int(downloaded_file.content_length) <= range_length
        assert int(downloaded_file.content_length) == len(downloaded_file.content)

        await client.close()

    @pytest.mark.asyncio
    @pytest.mark.order(2)
    async def test_download_params(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)
        file = ValueStorage.test_upload_file
        assert isinstance(file, File)

        content_disposition = f'attachment; filename="filename.jpg"'
        content_language = 'de-DE'
        expires = 'Wed, 21 Oct 2015 07:28:00 GMT'
        # TODO: this is a valid value for cache-control, but DownloadedFile tries to parse it as a timestamp
        # cache_control = 'max-age=604800, must-revalidate'
        content_encoding = 'compress'
        content_type = 'text/html;charset=utf-8'

        downloaded_file = await client.download_file_by_name(
            file_name=file.name,
            bucket_name=os.environ['BUCKET_NAME'],
            content_disposition=content_disposition,
            content_language=content_language,
            expires=expires,
            # cache_control=cache_control,
            content_encoding=content_encoding,
            content_type=content_type
        )

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert downloaded_file.content == path.read_bytes()
        assert downloaded_file.content_disposition == content_disposition
        assert downloaded_file.content_language == content_language
        # TODO: cache-control header is not exposed by DownloadedFile, and the logic that sets expires needs some
        #       attention
        # assert downloaded_file.cache_control == cache_control
        # assert downloaded_file.expires == expires
        assert downloaded_file.content_encoding == content_encoding
        assert downloaded_file.content_type == content_type

        # Download (by id)

        downloaded_file = await client.download_file_by_id(file_id=file.id)

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert downloaded_file.content == path.read_bytes()

        await client.close()
