from rich.console import Console
from rich.logging import RichHandler

import logging


console = Console()

# create logger
logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(console=console, rich_tracebacks=True, tracebacks_show_locals=False)
    ],
)
logger = logging.getLogger("SentinelProbe")
logger.setLevel(logging.INFO)
