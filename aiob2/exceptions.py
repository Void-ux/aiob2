from typing import NamedTuple


class B2Exception(Exception):
    """Base exception for all B2-related exceptions."""


class B2BadRequest(B2Exception):
    """The request had the wrong fields or illegal values."""


class B2Unauthorised(B2Exception):
    """The applicationKeyId and/or the applicationKey are wrong."""


class B2Unsupported(B2Exception):
    """The applicationKeyId is valid, but cannot be used with this version of the B2 API."""


class B2TransactionCapExceeded(B2Exception):
    """Usage cap exceeded."""


class B2BadAuthToken(B2Exception):
    """The auth token used is not valid. Call b2_authorize_account again to either get a new one."""


class B2ExpiredAuthToken(B2Exception):
    """The auth token used has expired. Call b2_authorize_account again to get a new one."""


class B2StorageCapExceeded(B2Exception):
    """Usage cap exceeded."""


class B2ServiceUnavailable(B2Exception):
    """Backblaze's services are unavailable, refer to the message."""


class B2CapExceeded(B2Exception):
    """You have exceeded your cap."""


class B2MethodNotAllowed(B2Exception):
    """You have used the wrong method for your operation."""


class B2RequestTimeout(B2Exception):
    """The service timed out reading the uploaded file."""


class B2AccessDenied(B2Exception):
    """The provided customer-managed encryption key is wrong."""


class B2DownloadCapExceeded(B2Exception):
    """Usage cap exceeded."""


class B2NotFound(B2Exception):
    """File is not in B2 Cloud Storage."""


class B2RangeNotSatisfiable(B2Exception):
    """The Range header in the request is valid but cannot be satisfied for the file."""


class B2Error(NamedTuple):
    status: int
    code: str


codes = {
    B2Error(400, 'bad_request'): B2BadRequest,
    B2Error(400, 'file_not_present'): B2BadRequest,

    B2Error(401, 'unauthorized'): B2Unauthorised,
    B2Error(401, 'unsupported'): B2Unsupported,
    B2Error(401, 'bad_auth_token'): B2BadAuthToken,
    B2Error(401, 'expired_auth_token'): B2ExpiredAuthToken,

    B2Error(403, 'transaction_cap_exceeded'): B2TransactionCapExceeded,
    B2Error(403, 'storage_cap_exceeded'): B2StorageCapExceeded,
    B2Error(403, 'access_denied'): B2AccessDenied,
    B2Error(403, 'download_cap_exceeded'): B2DownloadCapExceeded,

    B2Error(404, 'not_found'): B2NotFound,

    B2Error(405, 'method_not_allowed'): B2MethodNotAllowed,

    B2Error(408, 'request_timeout'): B2RequestTimeout,

    B2Error(416, 'range_not_satisfiable'): B2RangeNotSatisfiable,

    B2Error(503, 'service_unavailable'): B2ServiceUnavailable

}
