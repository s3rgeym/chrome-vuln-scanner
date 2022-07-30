import abc
import asyncio
import base64
import cgi
import json as jsonlib
import re
import urllib.parse
from collections import namedtuple
from copy import deepcopy
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Literal

import aiohttp
import yarl

from . import devtools
from .logger import get_logger
from .typing import Cookies

logger = get_logger()

RUSSIAN_DOMAINS = ('.by', '.ru', '.su')

BLACKLIST = (
    r'github\w*',
    'gmail',
    r'google\w*',
    'gstatic',
    'youtube',
)

# Должно отработать с mail.google.com
BLACKLIST_RE = re.compile(r'\b(' + '|'.join(BLACKLIST) + r')\b')


ALLOWED_VERBS = (
    'DELETE',
    'GET',
    'POST',
    'PATCH',
    'PUT',
)

QUOTES = '\'"'

# NORMAL_STATUSES = [200, 201, 401, 403, 404]
# ERROR_STATUSES = [400, *range(500, 600)]

SQLI_ERROR: re.Pattern = re.compile(
    '|'.join(
        [
            'You have an error in your SQL syntax',
            'Unclosed quotation mark after the character string',
            # Иногда при ошибке выводится полный запрос
            r'SELECT \* FROM',
            # Название PHP функций
            r'mysqli?_\w+',
            # bitrix
            '<b>DB query error.</b>',
            # pg_query
            'Query failed',
            # common PHP errors
            '<b>(?:Fatal error|Warning)</b>:',
        ]
    )
)

TITLE_RE = re.compile(r'<title>(.*)</title>', re.DOTALL)


@dataclass
class HTTPMessage(metaclass=abc.ABCMeta):
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
    debug_client: devtools.DebugClient

    @cached_property
    def payload(self) -> Payload | None:
        if not self.hasPostData:
            return
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
                    json=jsonlib.loads(self.postData),
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
    def debug_client(self) -> devtools.DebugClient:
        return self.request.debug_client

    async def body(self) -> str | bytes:
        missing = object()
        if getattr(self, '_body', missing) is missing:
            content = await self.debug_client.Network.getResponseBody(
                requestId=self.request_id
            )
            self._body = content['body']
            if content.get('base64Encoded'):
                self._body = base64.b64decode(self._body)
        return self._body

    async def json(self, *args: Any, **kwargs: Any) -> Any:
        assert self.mime[0] == 'application/json', "non json mime"
        data = await self.body()
        return jsonlib.loads(data, *args, **kwargs)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__} {self.status} {self.url}>'


@dataclass
class ChromeVulnScanner:
    remote_debugging_url: str = 'http://localhost:9222'

    async def handle_events(
        self,
        response_queue: asyncio.Queue,
        client: devtools.DevToolsClient,
        ws_debug_client_url: str,
    ) -> None:
        # {'description': '', 'devtoolsFrontendUrl': '/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/FC7B398840C0B738DC3980C2F5694A7C', 'faviconUrl': 'https://www.roguelynn.com/images/favicon.ico', 'id': 'FC7B398840C0B738DC3980C2F5694A7C', 'title': 'Exception Handling in asyncio – roguelynn', 'type': 'page', 'url': 'https://www.roguelynn.com/words/asyncio-exception-handling/', 'webSocketDebuggerUrl': 'ws://127.0.0.1:9222/devtools/page/FC7B398840C0B738DC3980C2F5694A7C'}
        debug_client = client.get_debug_client(ws_debug_client_url)
        await debug_client.Network.enable()
        # Отслеживание открытия новых табов
        # await debug_client.Target.setDiscoverTargets(discover=True)
        request_map = {}
        async for event in debug_client:
            try:
                params = event['params']
                match event['method']:
                    # Network.requestWillBeSentExtraInfo может срабатывать первее
                    # Network.requestWillBeSent, поэтому первый не подходит для
                    # перехвата cookies?
                    case 'Network.requestWillBeSent':
                        request = deepcopy(params['request'])
                        url = request['url']
                        sp = urllib.parse.urlsplit(url)
                        if sp.scheme not in ('http', 'https'):
                            logger.debug(
                                'not http: %s',
                                url[:37] + '...' if len(url) > 40 else url,
                            )
                            continue
                        hostname, _ = sp._hostinfo
                        if hostname.startswith('www.'):
                            hostname = hostname[len('www.') :]
                        # Не проверяем популярные сайты, например, тот же Google может по ip забанить
                        # Российские домены так же не трогаем
                        if BLACKLIST_RE.search(hostname) or hostname.endswith(
                            RUSSIAN_DOMAINS
                        ):
                            logger.debug("not allowed hostname: %s", hostname)
                            continue
                        request_map[params['requestId']] = request
                    case 'Network.responseReceived':
                        # Что делать, если запрос потеряется?
                        request_id = params['requestId']
                        raw_request = request_map.pop(request_id, None)
                        if raw_request is None:
                            logger.debug(
                                'request not found #%s (was skipped?)',
                                request_id,
                            )
                            continue
                        request = Request(raw_request, debug_client)
                        if request.method not in ALLOWED_VERBS:
                            logger.debug(
                                'skip request method: %s -  %s',
                                request.method,
                                request.url,
                            )
                            continue
                        raw_response = deepcopy(params['response'])
                        response = Response(raw_response, request)
                        if response.content_type in (
                            'text/html',
                            'application/json',
                        ):
                            logger.debug(
                                'skip response content-type: %s - %s',
                                response.content_type,
                                response.url,
                            ),
                            continue
                        if not response.ok:
                            logger.debug(
                                'skip response status: %d - %s',
                                response.status,
                                response.url,
                            )
                            continue
                        await response_queue.put(response)
                    # Новая вкладка
                    case 'Target.targetCreated':
                        # {'method': 'Target.targetCreated', 'params': {'targetInfo': {'targetId': 'EEF2A0496B417490EA57ECAE3916471E', 'type': 'page', 'title': 'New Tab', 'url': 'chrome://newtab/', 'attached': False, 'canAccessOpener': False, 'browserContextId': '49A9B68F915B0D0018D2588037D82389'}}}
                        info = event['params']['targetInfo']
                        if info['type'] != 'page' or info['attached']:
                            continue
            except Exception as e:
                logger.warn(e)

    async def test_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        params: Any,
        data: Any,
        json: Any,
    ) -> None:
        async with session.request(
            method,
            url,
            params=params,
            data=data,
            json=json,
        ) as response:
            contents = await response.text()
            if match := SQLI_ERROR.search(contents):
                logger.info('SQLi found!')
                try:
                    title = TITLE_RE.search(contents).group(1)
                except AttributeError:
                    title = None
                output = jsonlib.dumps(
                    {
                        k: v
                        for k, v in dict(
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json,
                            error=match.group(),
                            status=response.status,
                            title=title,
                        ).items()
                        if v is not None
                    }
                )
                print(output, flush=True)

    def value2str(self, val: Any) -> str:
        return val if isinstance(val, str) else jsonlib.dumps(val)

    async def handle_responses(
        self,
        response_queue: asyncio.Queue,
    ) -> None:
        while True:
            try:
                response: Response = await response_queue.get()
                request = response.request
                params = data = files = json = None
                if request.payload:
                    data, files, json = request.payload
                else:
                    params = dict(
                        urllib.parse.parse_qsl(
                            urllib.parse.urlsplit(request.url).query
                        )
                    )
                if not (params or data or json):
                    logger.debug('nothing to test: %s', response)
                    continue
                timeout = aiohttp.ClientTimeout(10.0)
                connector = aiohttp.TCPConnector(verify_ssl=False)
                async with aiohttp.ClientSession(
                    connector=connector, timeout=timeout
                ) as session:
                    headers = dict(request.headers)
                    headers.pop('Content-Type', 0)
                    session.headers = headers
                    cookies = await request.get_cookies()
                    session.cookie_jar.update_cookies(
                        cookies, response_url=response.url
                    )
                    kwargs = dict(params=params, data=data, json=json)
                    tasks = []
                    for dest, payload in kwargs.items():
                        if payload is None:
                            continue
                        for k, v in payload.items():
                            if isinstance(v, (list, dict)):
                                continue
                            kwargs_copy = deepcopy(kwargs)
                            kwargs_copy[dest][k] = self.value2str(v) + QUOTES
                            tasks.append(
                                self.test_request(
                                    request.method, request.url, **kwargs_copy
                                )
                            )
                    await asyncio.gather(*tasks, return_exceptions=True)

            except Exception as e:
                logger.warn(e)
            # finally:
            #     response_queue.task_done()

    async def run(self) -> None:
        response_queue = asyncio.Queue()
        async with aiohttp.ClientSession() as session:
            client = devtools.DevToolsClient(
                self.remote_debugging_url, session=session
            )
            for page in await client.get_pages():
                asyncio.ensure_future(
                    self.handle_events(
                        response_queue, client, page['webSocketDebuggerUrl']
                    )
                )
            await self.handle_responses(response_queue)
