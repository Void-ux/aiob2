import os
import pytest
import uuid
import asyncio
import logging
from pathlib import Path

from aiob2 import Client
from .conftest import ValueStorage

# we'll use the video here since the image often gets uploaded so quickly, it
# can do task 1 first, and then task 2 without any task-switching or vice versa
path = Path(__file__).resolve().parent / 'payloads/test_video.mp4'
bucket_id = os.environ['BUCKET_ID']


class TestParallelUploads:
    @pytest.mark.asyncio
    @pytest.mark.order(5)
    async def test_parallel_upload(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)
        data = path.read_bytes()
        # authenticate and set the upload URL/token, otherwise
        # each of the gather uploads will create their own
        # upload URLs and tokens, defeating the point of this
        # test.
        await client.upload_file(
            content_bytes=data,
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id
        )

        file1, file2 = await asyncio.gather(
            client.upload_file(
                content_bytes=data,
                content_type='image/jpeg',
                file_name=str(uuid.uuid4()),
                bucket_id=bucket_id
            ),
            client.upload_file(
                content_bytes=data,
                content_type='image/jpeg',
                file_name=str(uuid.uuid4()),
                bucket_id=bucket_id
            )
        )

        # should raise an error above if it fails, but we can double check
        # by ensuring data fields provided by Backblaze are not empty
        assert file1.content_length == file2.content_length
        assert file1.id and file2.id
        assert file1.account_id == file2.account_id

        ValueStorage.test_parallel1 = file1
        ValueStorage.test_parallel2 = file2

        await client.close()
