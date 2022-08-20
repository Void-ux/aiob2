import asyncio
import sys
import os
import pytest
from pathlib import Path

from aiob2 import Client, B2ConnectionInfo

# For local tests
if sys.platform == "win32":
    with open('C:\\Users\\MS1\\Desktop\\Projects\\aiob2\\tests\\.env', 'r') as file:
        for row in file:
            row = row.split('=')
            os.environ[row[0]] = row[1].replace('\n', '')

    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

path = Path(__file__).resolve().parent / 'payloads/test_image.jpg'
conn_info = B2ConnectionInfo(os.environ['KEY_ID'], os.environ['APP_ID'])
bucket_id = os.environ['BUCKET_ID']


class TestB2Actions:
    @pytest.mark.asyncio
    async def test_actions(self):
        client = Client(conn_info)
        # Upload

        file = await client.upload_file(
            content_bytes=path.read_bytes(),
            content_type='image/jpeg',
            file_name='test.jpg',
            bucket_id=bucket_id,
        )

        assert file.name == 'test.jpg'
        assert file.bucket_id == bucket_id
        assert file.content_type == 'image/jpeg'

        # Download (by name)

        downloaded_file = await client.download_file_by_name(file_name=file.name, bucket_name=os.environ['BUCKET_NAME'])

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert downloaded_file.upload_timestamp == file.upload_timestamp
        assert downloaded_file.content == path.read_bytes()

        # Download (by id)

        downloaded_file = await client.download_file_by_id(file_id=file.id)

        assert downloaded_file.name == file.name
        assert downloaded_file.id == file.id
        assert downloaded_file.upload_timestamp == file.upload_timestamp
        assert downloaded_file.content == path.read_bytes()

        # Delete

        deleted_file = await client.delete_file(file_name=file.name, file_id=file.id)

        assert deleted_file.name == file.name
        assert deleted_file.id == file.id

        account = await client._http.authorise_account()
        data = await client._http.request(f'{account.api_url}/b2api/v2/b2_list_buckets', method='GET', params={'accountId': account.account_id}, headers={'Authorization': account.authorisation_token})
        print(data)

        await client.close()
