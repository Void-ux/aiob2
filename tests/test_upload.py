import os
import pytest
import uuid
import logging
import datetime
from pathlib import Path

from aiob2 import Client
from .conftest import ValueStorage

path = Path(__file__).resolve().parent / 'payloads/test_image.jpg'
bucket_id = os.environ['BUCKET_ID']


class TestUpload:
    @pytest.mark.asyncio
    @pytest.mark.order(1)
    async def test_upload(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)
        file_name = str(uuid.uuid4())

        file = await client.upload_file(
            file_name=file_name,
            content_bytes=path.read_bytes(),
            bucket_id=bucket_id,
            content_type='image/jpeg',
            content_disposition='inline; filename="foo.jpg"',
            content_language=['en', 'ru'],
            expires=datetime.datetime.now() + datetime.timedelta(minutes=5),
            comments={'foo': 'bar'},
            server_side_encryption='AES256'
        )

        assert file.name == file_name
        assert file.bucket_id == bucket_id
        assert file.content_type == 'image/jpeg'
        assert file.server_side_encryption['algorithm'] == 'AES256'  # type: ignore

        # some more tests relating to this will be performed in the download,
        # such as, the disposition, language, expires and comments.

        ValueStorage.test_upload_file = file

        # ensure data is stored properly
        assert ValueStorage.test_upload_file == file

        await client.close()
