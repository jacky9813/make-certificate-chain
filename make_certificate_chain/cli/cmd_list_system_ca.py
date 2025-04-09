from .cli import cli
from .. import utils


@cli.command()
def list_system_ca():
    """
    List registered CA certificates within this system.
    """
    ca_list = utils.get_system_ca()

    for ca_subject in sorted(ca_list.keys(), key=lambda t: t.lower()):
        print(ca_subject)

