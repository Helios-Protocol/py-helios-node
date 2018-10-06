import pkg_resources

from helios.plugins.builtin.attach.plugin import (
    AttachPlugin
)
from helios.plugins.builtin.ethstats.plugin import (
    EthstatsPlugin,
)
from helios.plugins.builtin.fix_unclean_shutdown.plugin import (
    FixUncleanShutdownPlugin
)
from helios.plugins.builtin.json_rpc.plugin import (
    JsonRpcServerPlugin,
)
from helios.plugins.builtin.tx_pool.plugin import (
    TxPlugin,
)
from helios.plugins.builtin.light_peer_chain_bridge.plugin import (
    LightPeerChainBridgePlugin
)


def is_ipython_available() -> bool:
    try:
        pkg_resources.get_distribution('IPython')
    except pkg_resources.DistributionNotFound:
        return False
    else:
        return True


# This is our poor mans central plugin registry for now. In the future,
# we'll be able to load plugins from some path and control via Helios
# config file which plugin is enabled or not

ENABLED_PLUGINS = [
    AttachPlugin() if is_ipython_available() else AttachPlugin(use_ipython=False),
    EthstatsPlugin(),
    FixUncleanShutdownPlugin(),
    JsonRpcServerPlugin(),
    LightPeerChainBridgePlugin(),
    TxPlugin(),
]
