__all__ = ('DevToolsClient',)
from dataclasses import dataclass, field
from typing import Any

from aiohttp import ClientSession

from .debug import DebugClient
from .typing import ListItem


# https://chromedevtools.github.io/devtools-protocol/#endpoints
@dataclass
class DevToolsClient:
    base_url: str = 'http://localhost:9222/'
    session: ClientSession = field(default_factory=ClientSession)

    async def get(self, endpoint: str) -> Any:
        url = f"{self.base_url.rstrip('/')}/json/{endpoint.lstrip('/')}"
        response = await self.session.get(url)
        return await response.json()

    async def get_list(self) -> list[ListItem]:
        return await self.get('list')

    async def get_pages(self) -> list[ListItem]:
        return list(
            filter(lambda x: x['type'] == 'page', await self.get_list())
        )

    def get_debugger(self, ws_url: str) -> DebugClient:
        return DebugClient(ws_url, session=self.session)
