#!/usr/bin/env python3
from .cli import cli
import logging


LOG_FMT = "[%(asctime)s] %(filename)s:%(lineno)-3d %(levelname)s: %(message)s"
LOG_LEVEL = logging.INFO

root_logger = logging.root


def main():
    # Configuring logging
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=LOG_FMT))
    handler.setLevel(LOG_LEVEL)
    root_logger.addHandler(handler)
    root_logger.setLevel(LOG_LEVEL)
    for _, logger in logging.root.manager.loggerDict.items():
        if isinstance(logger, logging.Logger):
            # Removing custom handlers created by modules
            logger.handlers.clear()
            # While make sure the logs will reach root logger
            logger.propagate = True
            logger.setLevel(LOG_LEVEL)
    cli()


if __name__ == "__main__":
    main()
