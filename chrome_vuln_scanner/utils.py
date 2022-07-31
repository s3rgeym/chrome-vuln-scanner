from typing import Any


def filter_none(
    dic: dict[Any, Any] | None = None, **kwargs: Any
) -> dict[Any, Any]:
    return {k: v for k, v in dict(dic or {}, **kwargs).items() if v is not None}
