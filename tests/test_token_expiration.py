import datetime
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
    @pytest.mark.order(3)
    async def test_token_expiration(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)

        file1 = ValueStorage.test_token_expiration_file1 = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id
        )

        # Simulate token expiration;
        # BucketUploadInfo is read-only (NamedTuple)
        # so we'll need to re-instantiate it
        upload_info = client._http._upload_urls[bucket_id][0]  # type: ignore
        dummy_token = BucketUploadInfo(upload_info.url, 'foo', upload_info.created)
        client._http._upload_urls[bucket_id] = [dummy_token]  # type: ignore

        file2 = ValueStorage.test_token_expiration_file2 = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id
        )

        # should raise an error above if it fails, but we can double check
        # by ensuring data fields provided by Backblaze are not empty
        assert file1.content_length == file2.content_length
        assert file1.id and file2.id
        assert file1.account_id == file2.account_id

        # ensure that we actually generated a new token
        assert len(client._http._upload_urls[bucket_id]) == 1  # type: ignore
        upload_info2 = client._http._upload_urls[bucket_id][0]  # type: ignore
        assert upload_info.url != upload_info2.url
        assert upload_info.token != upload_info2.token
        assert upload_info.created != upload_info2.created

        await client.close()

    @pytest.mark.asyncio
    @pytest.mark.order(4)
    async def test_preemptive_token_expiration(self):
        client = Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG)

        file1 = ValueStorage.test_preemptive_token_expiration_file1 = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id
        )

        # Simulate pre-emptive token expiration handling;
        # BucketUploadInfo is read-only (NamedTuple)
        # so we'll need to re-instantiate it
        upload_info = client._http._upload_urls[bucket_id][0]  # type: ignore
        dummy_info = BucketUploadInfo(
            upload_info.url,
            upload_info.token,
            datetime.datetime.now() - datetime.timedelta(days=1)
        )
        client._http._upload_urls[bucket_id] = [dummy_info]  # type: ignore

        file2 = ValueStorage.test_preemptive_token_expiration_file2 = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name=str(uuid.uuid4()),
            bucket_id=bucket_id
        )

        # should raise an error above if it fails, but we can double check
        # by ensuring data fields provided by Backblaze are not empty
        assert file1.content_length == file2.content_length
        assert None not in (file1.id, file2.id)
        assert file1.account_id == file2.account_id

        # ensure that we actually generated a new token
        assert len(client._http._upload_urls[bucket_id]) == 1  # type: ignore
        upload_info2 = client._http._upload_urls[bucket_id][0]  # type: ignore
        assert upload_info.url != upload_info2.url
        assert upload_info.token != upload_info2.token
        assert upload_info.created != upload_info2.created

        await client.close()
