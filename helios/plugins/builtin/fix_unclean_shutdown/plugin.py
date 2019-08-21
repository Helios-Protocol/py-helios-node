from argparse import (
    ArgumentParser,
    Namespace,
    _SubParsersAction,
)
import time

from helios.config import (
    ChainConfig,
)
from helios.extensibility import (
    BaseMainProcessPlugin,
)
from helios.utils.ipc import (
    kill_process_id_gracefully,
    fix_unclean_shutdown)


class FixUncleanShutdownPlugin(BaseMainProcessPlugin):

    @property
    def name(self) -> str:
        return "Fix Unclean Shutdown"

    def configure_parser(self, arg_parser: ArgumentParser, subparser: _SubParsersAction) -> None:

        attach_parser = subparser.add_parser(
            'fix-unclean-shutdown',
            help='close any dangling processes from a previous unclean shutdown',
        )

        attach_parser.set_defaults(func=self.fix_unclean_shutdown)

    def fix_unclean_shutdown(self, args: Namespace, chain_config: ChainConfig) -> None:
        self.logger.info("Cleaning up unclean shutdown...")

        fix_unclean_shutdown(chain_config, self.logger)