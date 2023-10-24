from .cli import cli
from .. import VERSION

@cli.command()
def version():
    "Shows current program version"
    print(VERSION)
