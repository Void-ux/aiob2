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
