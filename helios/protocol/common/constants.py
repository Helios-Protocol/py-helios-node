from typing import Dict, Tuple

from eth_utils import (
    decode_hex,
)

from eth_keys import (
    keys,
)

from hvm.chains.mainnet import MAINNET_NETWORK_ID

from hp2p.kademlia import Address, Node

# The default timeout for a round trip API request and response from a peer.
ROUND_TRIP_TIMEOUT = 20.0

# Timeout used when performing the check to ensure peers are on the same side of chain splits as
# us.
CHAIN_SPLIT_CHECK_TIMEOUT = 15

# The defalt preferred nodes
DEFAULT_PREFERRED_NODES: Dict[int, Tuple[Node, ...]] = {
    MAINNET_NETWORK_ID: (
        Node(keys.PublicKey(decode_hex("1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082")),  # noqa: E501
             Address("52.74.57.123", 30303, 30303)),
        Node(keys.PublicKey(decode_hex("78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d")),  # noqa: E501
             Address("191.235.84.50", 30303, 30303)),
        Node(keys.PublicKey(decode_hex("ddd81193df80128880232fc1deb45f72746019839589eeb642d3d44efbb8b2dda2c1a46a348349964a6066f8afb016eb2a8c0f3c66f32fadf4370a236a4b5286")),  # noqa: E501
             Address("52.231.202.145", 30303, 30303)),
        Node(keys.PublicKey(decode_hex("3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99")),  # noqa: E501
             Address("13.93.211.84", 30303, 30303)),
    ),

}
