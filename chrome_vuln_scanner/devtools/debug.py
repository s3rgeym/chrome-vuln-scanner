"""Код стремно выглядит, но puppeteer сломался, поэтому пришлось писать свое"""
__all__ = (
    'DebugClient',
    'Error',
    'Event',
)

import asyncio
import dataclasses
import itertools
from dataclasses import dataclass, field
from typing import Any, ClassVar

import aiohttp
from aiohttp import ClientSession
from aiohttp.client import _WSRequestContextManager
from aiohttp.http_websocket import WSMessage

from .typing import ErrorData, Event


class Error(Exception):
    def __init__(self, err_data: ErrorData) -> None:
        self.code, self.message = err_data['code'], err_data['message']
        super().__init__(str(self))

    def __str__(self) -> str:
        return f'[{self.code}]: {self.message}'


@dataclass
class DebugClient:
    """Этот класс представляет собой вебсокет-клиент для работы с JSONRPC"""

    url: str
    session: ClientSession = field(default_factory=ClientSession)
    _: dataclasses.KW_ONLY
    autoconnect: bool = True
    ws: _WSRequestContextManager | None = field(default=None, init=False)
    pending: dict[int, asyncio.Future] = field(default_factory=dict, init=False)
    waitable: dict[str, asyncio.Future] = field(
        default_factory=dict, init=False
    )
    event_queue: asyncio.Queue = field(
        init=False, default_factory=asyncio.Queue
    )
    background_task: asyncio.Task | None = field(default=None, init=False)
    # TODO: нужен ли уникальный ID для каждого вызова метода?
    call_counter: ClassVar[itertools.count] = itertools.count()

    @property
    def connected(self) -> bool:
        return self.ws is not None and not self.ws.closed

    async def connect(self) -> None:
        if not self.connected:
            self.ws = await self.session.ws_connect(self.url)
            # Запускаем обработку сообщений в фоне
            # Я не уверен, что это лучший способ
            self.background_task = asyncio.ensure_future(self.handle_messages())

    async def handle_messages(self) -> None:
        msg: WSMessage
        async for msg in self.ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = msg.json()
                if 'result' in data:
                    self.pending[data['id']].set_result(data['result'])
                elif 'error' in data:
                    self.pending[data['id']].set_exception(Error(data['error']))
                else:
                    method = data.get('method')
                    if method in self.waitable:
                        self.waitable[method].cancel()
                    else:
                        # raise ValueError(data)
                        await self.event_queue.put(data)

    async def disconnect(self) -> None:
        if self.connected:
            await self.ws.close()
            self.background_task.cancel()
            await self.background_task
            self.ws = self.background_task = None

    async def __aenter__(self) -> 'DebugClient':
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    def __aiter__(self) -> 'DebugClient':
        return self

    # Для зацикливания
    # await for event in <DevToolsClient>
    async def __anext__(self) -> Event:
        try:
            return await self.event_queue.get()
        finally:
            self.event_queue.task_done()

    async def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None:
        if self.autoconnect:
            await self.connect()
        assert self.connected
        params = dict(params or {})
        params.update(kwargs)
        id_ = next(self.call_counter)
        data = {'id': id_, 'method': method, 'params': params}
        await self.ws.send_json(data)
        self.pending[id_] = asyncio.Future()
        await asyncio.wait_for(self.pending[id_], timeout=timeout)
        result = self.pending[id_].result()
        del self.pending[id_]
        return result

    # await <DevToolsClient>.wait_for('Network.loadingFinished')
    async def wait_for(self, method: str, timeout: float | None = None) -> None:
        self.waitable[method] = asyncio.Future()
        await asyncio.wait_for(self.waitable[method], timeout=timeout)
        del self.waitable[method]

    # await <DebugClient>.Network.enable()
    def __getattr__(self, name: str) -> 'Domain':
        return Domain(self, name)


@dataclass(frozen=True)
class Domain:
    DevToolsClient: DebugClient
    name: str

    def __getattr__(self, name: str) -> 'MethodCall':
        return MethodCall(self, name)


@dataclass(frozen=True)
class MethodCall:
    domain: Domain
    name: str

    def __getattr__(self, name: str) -> Any:
        return getattr(self.domain, name)

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return await self.DevToolsClient.call(
            f'{self.domain.name}.{self.name}', *args, **kwargs
        )
