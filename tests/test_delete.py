import os
import pytest
import logging

from aiob2 import Client, File
from .conftest import ValueStorage


class TestDelete:
    @pytest.mark.asyncio
    @pytest.mark.order(6)
    async def test_ctx_delete(self):
        async with Client(os.environ['KEY_ID'], os.environ['KEY'], log_level=logging.DEBUG) as client:
            c = 0
            for file in (files := (
                ValueStorage.test_upload_file,
                ValueStorage.test_token_expiration_file1,
                ValueStorage.test_token_expiration_file2,
                ValueStorage.test_preemptive_token_expiration_file1,
                ValueStorage.test_preemptive_token_expiration_file2,
                ValueStorage.test_parallel1,
                ValueStorage.test_parallel2,
                ValueStorage.test_large_upload_file
            )):
                if isinstance(file, File):
                    deleted_file = await client.delete_file(file_name=file.name, file_id=file.id)

                    assert deleted_file.name == file.name
                    assert deleted_file.id == file.id

                    c += 1

            # we'll do this separately to ensure every file was
            # removed from the ValueStorage on failed tests too
            assert len(files) == c
