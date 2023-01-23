from typing import Optional

from aiob2 import File


class ValueStorage:
    test_upload_file: Optional[File] = None
    test_token_expiration_file1: Optional[File] = None
    test_token_expiration_file2: Optional[File] = None
    test_large_upload_file: Optional[File] = None
