from typing import Any, TypedDict


class ListItem(TypedDict):
    description: str
    devtoolsFrontendUrl: str
    id: str
    title: str
    type: str
    url: str
    webSocketDebuggerUrl: str


# {'error': {'code': -32600, 'message': "Message must have integer 'id' property"}}
class ErrorData(TypedDict):
    code: int
    message: str


class Event(TypedDict):
    method: str
    params: dict[str, Any]
