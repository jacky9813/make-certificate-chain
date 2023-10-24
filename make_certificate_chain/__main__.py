#!/usr/bin/env python3
import logging
logging.basicConfig(
    format="[%(asctime)s] %(filename)s:%(lineno)d %(levelname)s: %(message)s",
    level=logging.INFO,
    handlers=[
        logging.StreamHandler()
    ]
)

from .cli import cli

def main():
    cli()

if __name__ == "__main__":
    cli()
