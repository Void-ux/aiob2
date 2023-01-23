import os
import pytest
import uuid
import logging
from pathlib import Path

from aiob2 import Client
from .conftest import ValueStorage

path = Path(__file__).resolve().parent / 'payloads/test_image.jpg'
bucket_id = os.environ['BUCKET_ID']


class TestLargeUpload:
    @pytest.mark.asyncio
    @pytest.mark.order(4)
    async def test_large_upload(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)

        file_name = str(uuid.uuid4())
        comments = {'foo': 'bar', 'spam': 'eggs'}
        large_file = await client.upload_large_file(bucket_id, file_name, comments=comments)

        size = 0
        with open(path, 'rb') as file:
            while True:
                # ideally we'd use the recommended_part_size, but
                # our test payload isn't above 100mb (typical
                # recommended part size).
                data = file.read(large_file.absolute_minimum_part_size)
                if len(data) == 0:
                    break
                await large_file.upload_part(content_bytes=data)
                size += len(data)

        file = await large_file.finish()

        # uploading one part isn't a proper test, so we'll ensure
        # at least two have been uploaded
        assert len(large_file._parts) > 1  # type: ignore

        assert file.name == file_name
        assert file.bucket_id == bucket_id
        assert file.content_length == size

        ValueStorage.test_large_upload_file = file

        # ensure data is stored properly
        assert ValueStorage.test_large_upload_file == file

        await client.close()
