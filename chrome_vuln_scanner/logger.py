import logging
from enum import Enum
from functools import lru_cache

CSI = '\033['

Color = Enum(
    'Color', 'black red green yellow blue magenta cyan white', start=30
)


class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        'DEBUG': Color.cyan,
        'INFO': Color.yellow,
        'WARNING': Color.red,
        'ERROR': Color.red,
        'CRITICAL': Color.red,
    }

    def format(self, record: logging.LogRecord) -> str:
        msg: str = super().format(record)
        if color := self.LEVEL_COLORS.get(record.levelname):
            msg = f'{CSI}{color.value}m{msg}{CSI}0m'
        return msg


@lru_cache
def get_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    console = logging.StreamHandler()
    formatter = ColorFormatter("%(levelname)-8s - %(message)s")
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger
