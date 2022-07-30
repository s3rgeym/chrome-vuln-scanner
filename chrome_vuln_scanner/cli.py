import argparse
import asyncio
from typing import Sequence

from .logger import get_logger
from .scanner import ChromeVulnScanner


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--remote-debugging-url', default='http://127.0.0.1:9222'
    )
    parser.add_argument(
        '-l',
        '--log-level',
        choices=['debug', 'info', 'warning', 'error', 'critical'],
    )
    args = parser.parse_args(argv)
    return args


def scan(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    if args.log_level:
        get_logger().setLevel(args.log_level.upper())
    scanner = ChromeVulnScanner(args.remote_debugging_url)
    asyncio.run(scanner.run())
