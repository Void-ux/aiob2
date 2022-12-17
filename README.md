# aiob2

---

<p align="center">
    <a href="https://www.python.org/downloads/">
        <img src="https://img.shields.io/pypi/pyversions/aiob2?style=for-the-badge" alt="Python version">
    </a>
    <a href="https://github.com/Void-ux/aiob2/actions">
        <img src="https://img.shields.io/github/actions/workflow/status/Void-ux/aiob2/build.yaml?branch=master&style=for-the-badge" alt="Build status">
    </a>
    <a href="https://pypi.org/project/aiob2/">
        <img src="https://img.shields.io/pypi/v/aiob2?color=8BC34A&style=for-the-badge" alt="PyPi">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/pypi/l/aiob2?color=C0C0C0&style=for-the-badge" alt="License">
    </a>
</p>

aiob2 is an asynchronous API wrapper for the [Backblaze B2 Bucket API](https://www.backblaze.com/b2/docs/calling.html).

It will allow you to interact with your B2 bucket, it's files and anything else that the B2 API allows in a modern, object-oriented fashion.

__**NOTE:**__ This API wrapper is by no means *complete* and has many endpoints to cover, though the main ones have been covered (they will be listed below)

## Installation

---

aiob2 is compatible with Python 3.8+ (this is an estimate). To install aiob2, run the following command in your (virtual) environment.

```
pip install aiob2
```

Alternatively, for the latest though least stable version, you can download it from the GitHub repo:

```
pip install git+https://github.com/Void-ux/aiob2.git
```

## Usage

### Uploading

```python
import aiohttp
import asyncio

from aiob2 import B2ConnectionInfo, Client

# Construct our connection info
conn_info = B2ConnectionInfo('key_id', 'app_id')

# Our image to upload to our bucket
with open(r'C:\Users\MS1\Pictures\Camera Roll\IMG_5316.jpeg', 'rb') as file:
    data = file.read()

async def main():
    client = Client(conn_info)
    file = await client.upload_file(
        content_bytes=data,
        content_type='image/jpeg',
        file_name='test.jpg',
        bucket_id='bucket_id',
    )
    await client.close()


if __name__ == '__main__':
    asyncio.run(main())
```

And that's it! `upload_file()` returns a `File` object that neatly wraps everything Backblaze's API has provided us with. The `File` object has the following **attributes**:

```
- account_id: str
- action: str
- bucket_id: str
- content_length: int
- content_sha1: str
- content_md5: str
- content_type: str
- id: str
- info: dict
- name: str
- retention: dict
- legal_hold: dict
- server_side_encryption: dict
- upload_timestamp: datetime.datetime
```

You can visit the [bucket.py](https://github.com/Void-ux/aiob2/blob/master/aiob2/types.py#L15-L29) file to view the source code of this class.

### Deleting

```python
# We can remove the boilerplate code and get straight to the method
deleted_file = await client.delete_file(file_name='file_name', file_id='file_id')
```

This will return a `DeletedFile` object, it has the following **attributes**:

```
- name: str
- id: str
```

### Downloading

Downloading a file can be done either with the `name` or the `id` of it.

```python
downloaded_file = await client.download_file_by_name(file_name='file_name', bucket_name='bucket_name')
```

```python
downloaded_file = await client.download_file_by_id(file_id='file_id')
```

This will return a `DownloadedFile` object with the following attributes:

```
- name: str
- id: str
- content_sha1: str
- upload_timestamp: datetime.datetime
- accept_ranges: str
- content: bytes
- content_type: str
- content_length: str
- date: str
```

**NOTE:** There are many kwargs you can provide when downloading a file, it's recommended to take a look at the source
code to see if any can benefit you and your usecase.

## License

---

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
