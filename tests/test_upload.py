import os
import pytest
import uuid
import logging
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
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=file_name,
            bucket_id=bucket_id,
        )

        assert file.name == file_name
        assert file.bucket_id == bucket_id
        assert file.content_type == 'image/jpeg'

        ValueStorage.test_upload_file = file

        # ensure data is stored properly
        assert ValueStorage.test_upload_file == file
