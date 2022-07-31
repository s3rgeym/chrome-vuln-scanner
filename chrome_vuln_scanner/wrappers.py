import base64
import cgi
import json
import urllib.parse
from abc import ABCMeta
from collections import namedtuple
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, TypedDict

from .devtools import DebugClient


# https://chromedevtools.github.io/devtools-protocol/tot/Network/#type-Cookie
class Cookie(TypedDict):
    name: str
    value: str
    ...


class Cookies(TypedDict):
    cookies: list[Cookie]


@dataclass
class HTTPMessage(metaclass=ABCMeta):
    raw: dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        return self.raw.get(name)

    @cached_property
    def mime(self) -> tuple[str, dict[str, str]]:
        return cgi.parse_header(self.headers.pop('Content-Type', ''))

    @property
    def content_type(self) -> str:
        return self.mime[0]

    @property
    def content_type_attrs(self) -> dict[str, str]:
        return self.mime[1]


Payload = namedtuple('Payload', 'data files json')

# https://chromedevtools.github.io/devtools-protocol/tot/Network/#type-Request
@dataclass(frozen=True)
class Request(HTTPMessage):
    debug_client: DebugClient
    payload: Payload = field(init=False)

    def __post_init__(self) -> None:
        self.payload = self.parse_payload()

    def parse_payload(self) -> Payload:
        if not self.hasPostData:
            return Payload(None, None, None)
        match self.content_type:
            case 'application/x-www-form-urlencoded':
                return Payload(
                    data=dict(urllib.parse.parse_qsl(self.postData)),
                    files=None,
                    json=False,
                )
            case 'application/json':
                return Payload(
                    data=None,
                    files=None,
                    json=json.loads(self.postData),
                )
            # https://stackoverflow.com/questions/33369306/parse-multipart-form-data-received-from-requests-post
            case _:
                raise ValueError(
                    "unexpected or unknown mime type: " + self.content_type
                )

    async def get_cookies(self) -> dict[str, str]:
        cookies: Cookies = await self.debug_client.Network.getCookies(
            urls=[self.url]
        )
        return {c['name']: c['value'] for c in cookies['cookies']}

    def __str__(self) -> str:
        return f'<{self.__class__.__name__} {self.method} {self.url}>'


# https://chromedevtools.github.io/devtools-protocol/tot/Network/#type-Response
@dataclass(frozen=True)
class Response(HTTPMessage):
    request: Request

    @property
    def ok(self) -> bool:
        return 300 > self.status >= 200

    @property
    def debug_client(self) -> DebugClient:
        return self.request.debug_client

    async def body(self) -> str | bytes:
        missing = object()
        if getattr(self, '_body', missing) is missing:
            result = await self.debug_client.Network.getResponseBody(
                requestId=self.request.id
            )
            self._body = result['body']
            if result.get('base64Encoded'):
                self._body = base64.b64decode(self._body)
        return self._body

    async def json(self, *args: Any, **kwargs: Any) -> Any:
        assert self.content_type == 'application/json', "non json mime"
        data = await self.body()
        return json.loads(data, *args, **kwargs)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__} {self.status} {self.url}>'
