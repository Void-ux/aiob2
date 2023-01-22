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

**NOTE:** This API wrapper is by no means *complete* and has many endpoints to cover, though the main ones have been covered (they will be listed below)

## Installation

---

aiob2 is compatible with Python 3.8+ (this is an estimate). To install aiob2, run the following command in your (virtual) environment.

```shell
pip install aiob2
```

Alternatively, for the latest though least stable version, you can download it from the GitHub repo:

```shell
pip install git+https://github.com/Void-ux/aiob2.git
```

## Usage

### Uploading

```python
import aiohttp
import asyncio

from aiob2 import Client

# Our image to upload to our bucket
with open(r'C:\Users\MS1\Pictures\Camera Roll\IMG_5316.jpeg', 'rb') as file:
    data = file.read()

async def main():
    async with Client('key_id', 'key') as client:
        file = await client.upload_file(
            content_bytes=data,
            file_name='test.jpg',
            bucket_id='bucket_id',
        )


if __name__ == '__main__':
    asyncio.run(main())
```

And that's it! `upload_file()` returns a `File` object that neatly wraps everything Backblaze's API has provided us with.
The `File` object's documentation can be found [here](https://aiob2.readthedocs.io/en/latest/pages/api.html#aiob2.File)

## License

---

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
