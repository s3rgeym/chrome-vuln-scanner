import asyncio
import json as jsonlib
import re
import urllib.parse
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import aiohttp

from . import devtools
from .logger import get_logger
from .utils import filter_none
from .wrappers import Request, Response

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


ALLOWED_METHODS = (
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
class ChromeVulnScanner:
    remote_debugging_url: str = 'http://localhost:9222'

    async def handle_page_events(
        self,
        client: devtools.DevToolsClient,
        ws_debug_client_url: str,
        sqli_queue: asyncio.Queue,
    ) -> None:
        # {'description': '', 'devtoolsFrontendUrl': '/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/FC7B398840C0B738DC3980C2F5694A7C', 'faviconUrl': 'https://www.roguelynn.com/images/favicon.ico', 'id': 'FC7B398840C0B738DC3980C2F5694A7C', 'title': 'Exception Handling in asyncio – roguelynn', 'type': 'page', 'url': 'https://www.roguelynn.com/words/asyncio-exception-handling/', 'webSocketDebuggerUrl': 'ws://127.0.0.1:9222/devtools/page/FC7B398840C0B738DC3980C2F5694A7C'}
        debug_client = client.get_debug_client(ws_debug_client_url)
        await debug_client.Network.enable()
        # Отслеживание открытия новых табов
        await debug_client.Target.setDiscoverTargets(discover=True)
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
                        if request.method not in ALLOWED_METHODS:
                            logger.debug(
                                'skip method: %s -  %s',
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
                                'skip content: %s - %s',
                                response.content_type,
                                response.url,
                            ),
                            continue
                        if not response.ok:
                            logger.debug(
                                'skip status: %d - %s',
                                response.status,
                                response.url,
                            )
                            continue
                        await sqli_queue.put(response)
                    # Открыта новая вкладка
                    case 'Target.targetCreated':
                        # {'method': 'Target.targetCreated', 'params': {'targetInfo': {'targetId': 'EEF2A0496B417490EA57ECAE3916471E', 'type': 'page', 'title': 'New Tab', 'url': 'chrome://newtab/', 'attached': False, 'canAccessOpener': False, 'browserContextId': '49A9B68F915B0D0018D2588037D82389'}}}
                        target_info = params['targetInfo']
                        if (
                            target_info['type'] != 'page'
                            or target_info['attached']
                        ):
                            continue
                        pages = await client.get_pages()
                        for page in pages:
                            if page['id'] != target_info['targetId']:
                                continue
                            asyncio.ensure_future(
                                self.handle_page_events(
                                    client,
                                    page['webSocketDebuggerUrl'],
                                    sqli_queue,
                                )
                            )
                            break
                    # Изменен URL
                    # https://chromedevtools.github.io/devtools-protocol/tot/Target/#event-targetInfoChanged
                    # https://chromedevtools.github.io/devtools-protocol/tot/Target/#type-TargetInfo
                    case 'Target.targetInfoChanged':
                        info = params['targetInfo']
                        logger.info('URL changed: %s', info['url'])
                        # Проверяем домен на /.git/config и тп
            except Exception as e:
                logger.warn(e)

    async def check_sqli(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        params: Any,
        headers: dict[str, str],
        data: Any,
        json: Any,
        **kwargs: Any,
    ) -> None:
        async with session.request(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            json=json,
            **kwargs,
        ) as response:
            contents = await response.text()
            if match := SQLI_ERROR.search(contents):
                logger.info('SQLi found!')
                output = jsonlib.dumps(
                    filter_none(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json,
                        error=match.group(),
                        status=response.status,
                        title=self.get_title(contents),
                    )
                )
                print(output, flush=True)

    @staticmethod
    def get_title(contents: str) -> str | None:
        try:
            return TITLE_RE.search(contents).group(1)
        except AttributeError:
            pass

    @staticmethod
    def value2str(val: Any) -> str:
        return val if isinstance(val, str) else jsonlib.dumps(val)

    async def scan_sqli(self, sqli_queue: asyncio.Queue) -> None:
        timeout = aiohttp.ClientTimeout(15.0)
        connector = aiohttp.TCPConnector(verify_ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout
        ) as session:
            while True:
                try:
                    response: Response = await sqli_queue.get()
                    request = response.request
                    data, files, json = request.payload
                    url = request.url.split('#')[0]
                    url, qs = url.split('?')
                    params = dict(urllib.parse.parse_qsl(qs))
                    if not (params or data or json):
                        logger.debug('nothing to test: %s', response)
                        continue
                    headers = request.headers.copy()
                    headers.pop('Content-Type', 0)
                    cookies = await request.get_cookies()
                    session.cookie_jar.update_cookies(
                        cookies, response_url=response.url
                    )
                    kw = dict(
                        headers=headers, params=params, data=data, json=json
                    )
                    for payload_key in ['params', 'data', 'json']:
                        payload = kw[payload_key]
                        if payload is None:
                            continue
                        for k, v in payload.items():
                            if isinstance(v, (list, dict)):
                                continue
                            kw_copy = deepcopy(kw)
                            kw_copy[payload_key][k] = self.value2str(v) + QUOTES
                            asyncio.ensure_future(
                                self.check_sqli(
                                    request.method,
                                    url,
                                    **kw_copy,
                                )
                            )
                except Exception as e:
                    logger.warn(e)
                # finally:
                #     sqli_queue.task_done()

    async def run(self) -> None:
        sqli_queue = asyncio.Queue()
        async with aiohttp.ClientSession() as session:
            client = devtools.DevToolsClient(
                self.remote_debugging_url, session=session
            )
            for page in await client.get_pages():
                asyncio.ensure_future(
                    self.handle_page_events(
                        client,
                        page['webSocketDebuggerUrl'],
                        sqli_queue,
                    )
                )
            await self.scan_sqli(sqli_queue)
