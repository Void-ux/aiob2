# aiob2

---

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img alt="Python Version" src="https://img.shields.io/badge/python-3.8.10-blue.svg?color=3776AB&style=for-the-badge">
  </a>
  <a href="https://pypi.org/project/aiob2/">
     <img src="https://img.shields.io/pypi/v/aiob2?color=8BC34A&style=for-the-badge" alt="PyPi">
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0.en.html">
     <img src="https://img.shields.io/pypi/l/aiob2?style=for-the-badge" alt="License">
  </a>
</p>

aiob2 is an asynchronous API wrapper for the [Backblaze B2 Bucket API](https://www.backblaze.com/b2/docs/calling.html).

It will allow you to interact with your B2 bucket, it's files and anything else that the B2 API allows in a modern, object-oriented fashion.

__**NOTE:**__ This API wrapper is by no means *complete* and has many endpoints to cover, though the main ones have been covered (they will be listed below)

# Installation

---

aiob2 is compatible with Python 3.8.10+ (this is an estimate). To install aiob2, run the following command in your (virtual) environment.
```
pip install aiob2
```
Alternatively, for the latest though least stable version, you can download it from the GitHub repo:
```
pip install git+https://github.com/Void-ux/aiob2.git
```

# Usage

### Uploading
```python
import aiohttp
import asyncio

from aiob2 import B2ConnectionInfo, bucket

# Construct our connection info
conn_info = B2ConnectionInfo('key_id', 'app_id')

# Our image to upload to our bucket
with open(r'C:\Users\MS1\Pictures\Camera Roll\IMG_5316.jpeg', 'rb') as file:
    data = file.read()

async def main():
    async with aiohttp.ClientSession() as s:
        await bucket.upload_file(
            content_bytes=data,
            content_type='image/jpeg',
            file_name='home.jpeg',
            session=s,
            bucket_id='bucket_id',
            conn_info=conn_info
        )


if __name__ == '__main__':
    asyncio.run(main())
```

And that's it! `upload_file()` returns a `File` object that neatly wraps everything Backblaze's API has provided us with. The `File` object has the following **attributes**:
```
account_id
action
bucket_id
content_length
content_sha1
content_md5
content_type
file_id
file_info
file_name
file_retention
legal_hold
server_side_encryption
upload_timestamp
```
You can visit the [bucket.py](https://github.com/Void-ux/aiob2/aiob2/bucket.py#L20-L66) file to view the source code of this class.

### Deleting

```python
# We can remove the boilerplate code and get straight to the method
from aiob2 import bucket

await bucket.delete_file(
    file_name='home.jpeg',
    file_id='4_z275c6d8d808e543872cc0215_f11088ad8814ee120_d20220514_m211709_c002_v0001096_t0019_u01652563029709',
    conn_info=conn_info,
    session=s
)
```
This will return a `DeletedFile` object, it has the following **attributes**:
```
file_name
file_id
```

# License

---

This project is released under the [MIT License](https://opensource.org/licenses/MIT).