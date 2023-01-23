import os
import pytest
import uuid
import logging
from pathlib import Path

from aiob2 import Client
from aiob2.http import BucketUploadInfo
from .conftest import ValueStorage

path = Path(__file__).resolve().parent / 'payloads/test_image.jpg'
bucket_id = os.environ['BUCKET_ID']


class TestTokenExpiration:
    @pytest.mark.asyncio
    @pytest.mark.order(2)
    async def test_token_expiration(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)

        file1 = ValueStorage.test_token_expiration_file1 = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id,
        )

        # Simulate token expiration;
        # BucketUploadInfo is read-only (NamedTuple)
        # so we'll need to re-instantiate it
        dummy_token = BucketUploadInfo(client._http._upload_urls[bucket_id].url, 'foo')  # type: ignore
        client._http._upload_urls[bucket_id] = dummy_token  # type: ignore

        file2 = ValueStorage.test_token_expiration_file2 = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id,
        )

        # should raise an error above if it fails, but we can double check
        # by ensuring data fields provided by Backblaze are not empty
        assert file1.content_length == file2.content_length
        assert None not in (file1.id, file2.id)
        assert file1.account_id == file2.account_id

        await client.close()
