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
)
from hvm.constants import ZERO_ADDRESS
from hvm.db.backends.level import LevelDB

from hvm import (
    MainnetChain,
    TestnetChain,
)
from hvm.chains.base import (
    BaseChain
)
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    MAINNET_NETWORK_ID,
    GENESIS_WALLET_ADDRESS,
)
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_NETWORK_ID,
    GENESIS_WALLET_ADDRESS as TESTNET_GENESIS_WALLET_ADDRESS,
)

class RebuildHistoricalChainPlugin(BaseMainProcessPlugin):

    @property
    def name(self) -> str:
        return "Rebuild Historical Chain"

    def configure_parser(self, arg_parser: ArgumentParser, subparser: _SubParsersAction) -> None:

        attach_parser = subparser.add_parser(
            'rebuild-historical-chain',
            help='Rebuilds the historical root hashes and chronological block windows',
        )

        attach_parser.set_defaults(func=self.rebuild_historical_chain)

    def rebuild_historical_chain(self, args: Namespace, chain_config: ChainConfig) -> None:
        self.logger.info("Rebuilding historical chain")
        base_db = LevelDB(db_path=chain_config.database_dir)

        if chain_config.network_id == MAINNET_NETWORK_ID:
            chain_class = MainnetChain
        elif chain_config.network_id == TESTNET_NETWORK_ID:
            chain_class = TestnetChain
        else:
            raise NotImplementedError(
                "Only the mainnet chain is currently supported"
            )

        chain = chain_class(base_db, ZERO_ADDRESS)

        chain.initialize_historical_root_hashes_and_chronological_blocks()

        self.logger.info("Finished rebuilding historical chain")

