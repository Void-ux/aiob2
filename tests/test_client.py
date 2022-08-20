import asyncio
import sys
import os

import aiohttp
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


class TestClient:
    @pytest.mark.asyncio
    async def test_actions(self):
        # Testing that supplying an aiohttp session works, and the __aenter__ works
        session = aiohttp.ClientSession()

        async with Client(conn_info, session) as client:
            file = await client.upload_file(
                content_bytes=path.read_bytes(),
                content_type='image/jpeg',
                file_name='test.jpg',
                bucket_id=bucket_id,
            )

            await client.delete_file(file_name=file.name, file_id=file.id)

        assert client._http._session.closed  # type: ignore since we made an action, a session is guaranteed to have been created
