import datetime
import json
from typing import Any

try:
    import orjson  # type: ignore
except ModuleNotFoundError:
    HAS_ORJSON = False
else:
    HAS_ORJSON = True

__all__ = ('format_timestamp', '_to_json', '_from_json')


def format_timestamp(timestamp: float) -> datetime.datetime:
    """Formats a UTC float timestamp represented in milliseconds.

    Parameters
    ----------
    timestamp: :class:`float`
        The UTC timestamp in milliseconds.
    """
    # shifts the decimal point 3 digits to the left
    timestamp /= 1000.

    return datetime.datetime.utcfromtimestamp(timestamp)


class _MissingSentinel:
    __slots__ = ()

    def __eq__(self, other) -> bool:
        return False

    def __bool__(self) -> bool:
        return False

    def __hash__(self) -> int:
        return 0

    def __repr__(self):
        return '...'


MISSING: Any = _MissingSentinel()

if HAS_ORJSON:

    def _to_json(obj: Any) -> str:
        return orjson.dumps(obj).decode('utf-8')

    _from_json = orjson.loads  # type: ignore

else:

    def _to_json(obj: Any) -> str:
        return json.dumps(obj, separators=(',', ':'), ensure_ascii=True)

    _from_json = json.loads
