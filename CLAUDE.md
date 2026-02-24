# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

aiob2 is an async Python wrapper for the Backblaze B2 Native API. It uses aiohttp for HTTP and provides an object-oriented interface for bucket/file operations. Published on PyPI as `aiob2`.

## Commands

```shell
# Install dependencies
poetry install

# Run all tests (requires real B2 credentials, see below)
poetry run pytest

# Run a single test file
poetry run pytest tests/test_upload.py

# Run a specific test
poetry run pytest tests/test_upload.py::test_upload

# Type checking (strict mode)
poetry run pyright

# Build docs
cd docs && make html
```

### Test Environment Variables

Tests are integration tests against the live Backblaze B2 API (no mocks). They require:
- `BUCKET_ID` — target bucket ID
- `BUCKET_NAME` — target bucket name
- `KEY_ID` — Backblaze application key ID
- `KEY` — Backblaze application key

Tests are **ordered** via `pytest-order` and share state through `ValueStorage` in `conftest.py` (e.g., uploaded file IDs are reused in download/delete tests). Running tests out of order or individually may fail due to missing shared state.

## Architecture

### Two-layer client design

```
Client (bucket.py)  — public API, what users interact with
    ↓
HTTPClient (http.py) — auth, routing, retry, upload URL pooling
    ↓
Models (models/)     — TypedDict payloads wrapped into dataclass-like objects
```

- **`Client`** (`bucket.py`): All public methods (upload, download, delete, large file operations). Delegates HTTP to `HTTPClient`.
- **`HTTPClient`** (`http.py`): Manages auth lifecycle, lazy `aiohttp.ClientSession` creation, retry with exponential backoff (5 attempts), and upload URL pooling per bucket. `Route` class encapsulates method + URL using `yarl.URL`.
- **`models/`**: `B2Object` base class (in `archetypes.py`) provides `__repr__`. `File`, `DeletedFile`, `DownloadedFile` wrap API response TypedDicts. `account.py` has auth payload types.
- **`LargeFile`** (`file.py`): Handles chunked uploads with `asyncio.Queue` + concurrent workers and `aiofiles` for async I/O.

### Key patterns

- **Upload URL pooling**: `HTTPClient` caches upload URLs per bucket/large-file ID in `DefaultDict[str, List[UploadInfo]]`. URLs are valid 24 hours; `UploadInfo` uses context manager protocol to track `in_use` state for safe concurrent access.
- **MISSING sentinel** (`utils.py`): Custom falsy sentinel for optional params (discord.py pattern). Distinct from `None`.
- **Optional orjson**: `pip install aiob2[speed]` enables faster JSON via orjson (falls back to stdlib json).
- **API version**: Base route is `/b2api/v1` but individual routes may override to v2 paths.
- **asyncio_mode = "strict"** in pytest config — all async tests need explicit `@pytest.mark.asyncio`.
