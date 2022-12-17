from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from aiohttp import ClientResponse

__all__ = ('HTTPException', 'RateLimited', 'Unauthorized', 'Forbidden', 'NotFound', 'BackblazeServerError')


class BackblazeException(Exception):
    """Base exception class for aiob2.

    Ideally speaking, this could be caught to handle any exceptions raised from this library.
    """

    pass


class HTTPException(BackblazeException):
    """Exception that's raised when a HTTP request operation fails.

    Attributes
    ------------
    response: :class:`aiohttp.ClientResponse`
        The response of the failed HTTP request. This is an
        instance of :class:`aiohttp.ClientResponse`.
    status: :class:`int`
        The code code of the HTTP request.
    text: :class:`str`
        The Spotify specific error code for the failure.
    """
    def __init__(self, response: ClientResponse, message: Dict[str, Any]):
        self.response: ClientResponse = response
        self.status: int = response.status
        self.code: str = message['code']
        self.text: str = message['message']

        fmt = '{0.status} (error code: {1}) {0.reason}: {2}'

        super().__init__(fmt.format(self.response, self.code, self.text))


class RateLimited(HTTPException):
    """Exception that's raised for when status code 429 occurs.

    Subclass of :exc:`HTTPException`
    """

    pass


class Unauthorized(HTTPException):
    """Exception that's raised for when status code 401 occurs.

    Subclass of :exc:`HTTPException`
    """

    pass


class Forbidden(HTTPException):
    """Exception that's raised for when status code 403 occurs.

    Subclass of :exc:`HTTPException`
    """

    pass


class NotFound(HTTPException):
    """Exception that's raised for when status code 404 occurs.

    Subclass of :exc:`HTTPException`
    """

    pass


class BackblazeServerError(Exception):
    """Exception that's raised for when a 500 range status code occurs.

    Subclass of :exc:`HTTPException`.
    """

    pass
