from typing import TypedDict


# https://chromedevtools.github.io/devtools-protocol/tot/Network/#type-Cookie
class Cookie(TypedDict):
    name: str
    value: str
    ...


class Cookies(TypedDict):
    cookies: list[Cookie]
