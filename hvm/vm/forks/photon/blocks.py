from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock, HeliosTestnetQueueBlock
from rlp_cython.sedes import (
    CountableList,
)
from hvm.rlp.headers import (
    BlockHeader,
    MicroBlockHeader)

from .transactions import (
    PhotonReceiveTransaction, PhotonTransaction)

from hvm.rlp.receipts import (
    Receipt,
)
from hvm.rlp.consensus import StakeRewardBundle

class PhotonMicroBlock(HeliosMicroBlock):
    fields = [
        ('header', MicroBlockHeader),
        ('transactions', CountableList(PhotonTransaction)),
        ('receive_transactions', CountableList(PhotonReceiveTransaction)),
        ('reward_bundle', StakeRewardBundle),
    ]

class PhotonBlock(HeliosTestnetBlock):
    transaction_class = PhotonTransaction
    receive_transaction_class = PhotonReceiveTransaction
    header_class = BlockHeader
    reward_bundle_class = StakeRewardBundle
    receipt_class = Receipt

    fields = [
        ('header', header_class),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class)),
        ('reward_bundle', reward_bundle_class),
    ]



class PhotonQueueBlock(PhotonBlock,HeliosTestnetQueueBlock):
    transaction_class = PhotonTransaction
    receive_transaction_class = PhotonReceiveTransaction
    reward_bundle_class = StakeRewardBundle
    receipt_class = Receipt

    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class)),
        ('reward_bundle', StakeRewardBundle),
    ]

    def as_complete_block(self, private_key, chain_id):
        # first lets sign the header
        """
        signs the header of the given block and changes it to a complete block
        doesnt validate the header before doing so
        """

        signed_header = self.header.get_signed(private_key, chain_id)

        return PhotonBlock(signed_header, self.transactions, self.receive_transactions, self.reward_bundle)