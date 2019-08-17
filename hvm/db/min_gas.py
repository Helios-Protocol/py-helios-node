import bisect
import functools
import itertools
import logging
import time
from uuid import UUID

from abc import (
    ABCMeta,
    abstractmethod
)
from typing import (
    cast,
    Dict,
    Iterable,
    List,
    Set,
    Tuple,
    Type,
    TYPE_CHECKING,
    Union,
    Optional,
)

from hvm.utils.pid import clamp
from hvm.types import Timestamp

import rlp_cython as rlp

from trie import (
    HexaryTrie,
)

from eth_typing import (
    BlockNumber,
    Hash32,
    Address
)

from eth_utils import (
    to_list,
    to_tuple,
)

from eth_hash.auto import keccak

from hvm.constants import (
    GENESIS_PARENT_HASH,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH,
    MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE,
    MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP,
    ZERO_HASH32,
    BLANK_REWARD_HASH, MIN_GAS_PRICE_CALCULATION_GOAL_TX_PER_CENTISECOND_MUTIPLIER)
from hvm.exceptions import (
    CanonicalHeadNotFound,
    HeaderNotFound,
    ParentNotFound,
    TransactionNotFound,
    JournalDbNotActivated,
    HistoricalNetworkTPCMissing,
    HistoricalMinGasPriceError,
)
from hvm.db.backends.base import (
    BaseDB
)
from hvm.db.schema import SchemaV1
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.rlp.receipts import (
    Receipt
)
from hvm.utils.hexadecimal import (
    encode_hex,
)
from hvm.validation import (
    validate_uint256,
    validate_is_integer,
    validate_word,
    validate_canonical_address,
    validate_centisecond_timestamp,
    validate_is_bytes,
)

from hvm.rlp.consensus import StakeRewardBundle, BaseRewardBundle, NodeStakingScore
from hvm.rlp import sedes as evm_rlp_sedes
from hvm.rlp.sedes import(
    trie_root,
    address,
    hash32,

)

import math
from hvm.utils.pid import PID

from rlp_cython.sedes import(
    big_endian_int,
    CountableList,
    binary,
)


from hvm.db.journal import (
    JournalDB,
)

from sortedcontainers import (
    SortedList,
    SortedDict,
)

from hvm.utils.numeric import (
    are_items_in_list_equal,
)

from hvm.utils.padding import de_sparse_timestamp_item_list, propogate_timestamp_item_list_to_present
if TYPE_CHECKING:
    from hvm.rlp.blocks import (  # noqa: F401
        BaseBlock
    )
    from hvm.rlp.transactions import (  # noqa: F401
        BaseTransaction,
        BaseReceiveTransaction
    )

class BaseMinGasDB(metaclass=ABCMeta):
    db = None  # type: BaseDB

    @abstractmethod
    def __init__(self, db: BaseDB) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_historical_minimum_gas_price(self,
                                          historical_minimum_gas_price: List[List[Union[Timestamp, int]]]) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def load_historical_minimum_gas_price(self, sort: bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def append_historical_min_gas_price_now(self, min_gas_price: int) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_now_as_last_min_gas_price_PID_update(self) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_time_since_last_min_gas_price_PID_update(self) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_historical_tx_per_decisecond_from_imported(self, historical_tx_per_centisecond: List[List[int]], de_sparse=True) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def load_historical_tx_per_decisecond_from_imported(self, sort=False) -> Optional[List[List[int]]]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_tpd_tail(self) -> List[int]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_historical_network_tpc_capability(self, historical_tpc_capability: List[List[Union[Timestamp, int]]],
                                               de_sparse: bool = False) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_current_historical_network_tpc_capability(self, current_tpc_capability: int) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def load_historical_network_tpc_capability(self, sort: bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def _calculate_next_min_gas_price_pid(self, historical_txpd: List[int], last_min_gas_price: int, wanted_txpd: int) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def initialize_historical_minimum_gas_price_at_genesis(self, min_gas_price: int, net_tpc_cap: int) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")


    @abstractmethod
    def get_required_block_min_gas_price(self) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def min_gas_system_initialization_required(self) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

class MinGasDB(BaseMinGasDB):
    logger = logging.getLogger('hvm.db.MinGasDB')
    _journaldb = None

    def __init__(self, db: BaseDB) -> None:
        self.db = db


    #
    # Historical minimum allowed gas price API for throttling the network
    #
    def save_historical_minimum_gas_price(self, historical_minimum_gas_price: List[List[Union[Timestamp, int]]]) -> None:
        '''
        This takes list of timestamp, gas_price. The timestamps are every 100 seconds
        The min gas price is multiplied by 100 to save decimals
        '''
        data_to_save = []
        for timestamp_gas_price in historical_minimum_gas_price:
            data_to_save.append([timestamp_gas_price[0], int(timestamp_gas_price[1]*100)])

        lookup_key = SchemaV1.make_historical_minimum_gas_price_lookup_key()
        encoded_data = rlp.encode(data_to_save[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )


    def load_historical_minimum_gas_price(self, sort:bool = True, return_int = True) -> Optional[List[List[Union[Timestamp, int]]]]:
        '''
        saved as timestamp, min gas price
        It is now divided by 100 to get decimals back
        '''
        lookup_key = SchemaV1.make_historical_minimum_gas_price_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])), use_list = True)
            if sort:
                if len(data) > 0:
                    data.sort()

            return_data = []
            for timestamp_gas_price in data:
                if return_int:
                    return_data.append([timestamp_gas_price[0], int(timestamp_gas_price[1]/100)])
                else:
                    return_data.append([timestamp_gas_price[0], timestamp_gas_price[1] / 100])

            return return_data
        except KeyError:
            return None


    def append_historical_min_gas_price_now(self, min_gas_price: int) -> None:

        current_centisecond_window = int(time.time() / 100) * 100

        hist_min_gas_price = self.load_historical_minimum_gas_price(return_int = False)

        current_entry = [current_centisecond_window, min_gas_price]

        if hist_min_gas_price is None:
            new_hist_min_gas_price = [current_entry]
        else:
            # cycle backwards through the existing and delete any newer or equal timestamps, then append our new one.
            for i in range(len(hist_min_gas_price)-1, -1, -1):
                if hist_min_gas_price[i][0] >= current_centisecond_window:
                    del(hist_min_gas_price[i])
            hist_min_gas_price.append(current_entry)
            new_hist_min_gas_price = hist_min_gas_price

        self.save_historical_minimum_gas_price(new_hist_min_gas_price)


    def save_now_as_last_min_gas_price_PID_update(self) -> None:
        now = int(time.time())
        lookup_key = SchemaV1.make_min_gas_system_last_pid_time_key()
        encoded_data = rlp.encode(now,sedes=rlp.sedes.f_big_endian_int)
        self.db.set(
            lookup_key,
            encoded_data,
        )


    def get_time_since_last_min_gas_price_PID_update(self) -> int:
        lookup_key = SchemaV1.make_min_gas_system_last_pid_time_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.f_big_endian_int)
        except KeyError:
            data = 0

        time_since = int(time.time()) - data
        if time_since >= 10:
            #limit to 10 so that we don't get a crazy huge result from the PID
            return 10
        elif time_since <= 0:
            return 0
        else:
            return time_since




    def save_historical_tx_per_decisecond_from_imported(self, historical_tx_per_decisecond: List[List[int]], de_sparse = True) -> None:
        '''
        This takes list of timestamp, tx_per_centisecond.
        this one is naturally a sparse list because some 100 second intervals might have no tx. So we can de_sparse it.
        '''
        if de_sparse:
            historical_tx_per_decisecond = de_sparse_timestamp_item_list(historical_tx_per_decisecond, 10, filler = 0)
        lookup_key = SchemaV1.make_historical_tx_per_decisecond_lookup_key()
        encoded_data = rlp.encode(historical_tx_per_decisecond[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )


    def load_historical_tx_per_decisecond_from_imported(self, sort = True) -> List[Tuple[int, int]]:
        '''
        returns a list of [timestamp, tx/centisecond]
        '''

        lookup_key = SchemaV1.make_historical_tx_per_decisecond_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])), use_list=True)
            if sort:
                if len(data) > 0:
                    data.sort()
            return data
        except KeyError:
            return []

    def append_transaction_count_to_historical_tx_per_decisecond_from_imported(self, tx_count: int) -> None:
        self.logger.debug("Adding {} tx to historical tx per decisecond count".format(tx_count))
        hist_txpd = self.load_historical_tx_per_decisecond_from_imported()
        current_decisecond = int(time.time() / 10) * 10

        if len(hist_txpd) == 0:
            hist_txpd = [[current_decisecond, tx_count]]
        else:
            # cycle backwards through the existing and delete any newer timestamps
            for i in range(len(hist_txpd) - 1, -1, -1):
                if hist_txpd[i][0] > current_decisecond:
                    del (hist_txpd[i])

            # If the timestamp aleady exists, then add the new tx count
            # otherwise, append a new entry
            if hist_txpd[-1][0] == current_decisecond:
                hist_txpd[-1][1] += tx_count
            else:
                hist_txpd.append([current_decisecond, tx_count])

        self.save_historical_tx_per_decisecond_from_imported(hist_txpd)

    def get_tpd_tail(self) -> List[int]:
        #
        # Returns the last 2 complete historical_tx_per_decisecond windows
        # Tries it's best to return something useful if there isnt enough data
        #
        current_decisecond = int(time.time() / 10) * 10
        newest_complete_window = current_decisecond-10

        tail = [0,0]
        hist_txpd = self.load_historical_tx_per_decisecond_from_imported()
        if len(hist_txpd) != 0:
            for timestamp_txpd in reversed(hist_txpd):
                if timestamp_txpd[0] == newest_complete_window:
                    tail[1] = timestamp_txpd[1]
                if timestamp_txpd[0] == newest_complete_window-10:
                    tail[0] = timestamp_txpd[1]
                if timestamp_txpd[0] < (newest_complete_window-10):
                    break

        return tail

    def save_historical_network_tpc_capability(self, historical_tpc_capability: List[List[Union[Timestamp, int]]], de_sparse: bool = False) -> None:
        '''
        This takes list of timestamp, historical_tpc_capability. The timestamps are 100 seconds, historical_tpc_capability must be an intiger
        '''
        if de_sparse:
            historical_tpc_capability = de_sparse_timestamp_item_list(historical_tpc_capability, 100, filler = None)
        lookup_key = SchemaV1.make_historical_network_tpc_capability_lookup_key()
        encoded_data = rlp.encode(historical_tpc_capability[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )


    def save_current_historical_network_tpc_capability(self, current_tpc_capability: int) -> None:
        validate_uint256(current_tpc_capability, title="current_tpc_capability")
        if current_tpc_capability < 1:
            current_tpc_capability = 1

        existing = self.load_historical_network_tpc_capability()
        current_centisecond = int(time.time()/100) * 100
        if existing is None:
            existing = [[current_centisecond, current_tpc_capability]]
        else:
            existing.append([current_centisecond, current_tpc_capability])
        self.save_historical_network_tpc_capability(existing, de_sparse = True)



    def load_historical_network_tpc_capability(self, sort:bool = True) -> Optional[List[List[Union[Timestamp, int]]]]:
        '''
        Returns a list of [timestamp, transactions per second]
        :param mutable:
        :param sort:
        :return:
        '''
        lookup_key = SchemaV1.make_historical_network_tpc_capability_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])), use_list = True)
            if sort:
                if len(data) > 0:
                    data.sort()

            return data
        except KeyError:
            return None

    #
    # New PID min gas price stuff.
    #
    def _calculate_next_min_gas_price_pid(self, historical_txpd: List[int], last_min_gas_price: int, wanted_txpd: int, time_since_last_pid_update: int = 10) -> int:
        #
        # This uses a simple PID to increase the minimum gas price and throttle transactions. It is very aggressive
        # so that it can catch dos attacks. It expects historical_txpd to be the transactions per 10 seconds, in 10 second
        # increments.
        #
        num_seconds_between_points =time_since_last_pid_update
        if len(historical_txpd) < 2:
            self.logger.debug("Not enough historical txpd to calculate next min gas price. Returning previous min gas price.")
            return last_min_gas_price

        #
        # PID PARAMS
        #
        # Kp = 0.1
        # Ki = 0.3
        # Kd = 0.005
        Kp = 3
        Ki = 9
        Kd = 0.05
        output_limits = (None, -1)

        # compute error terms - scale by wanted_txpd so that we get the same behavior over a wide range
        error = (wanted_txpd - historical_txpd[-1])/wanted_txpd
        d_txpd = historical_txpd[-1] - historical_txpd[-2]

        # compute the proportional term
        _proportional = Kp * error

        # compute integral and derivative terms
        _last_integral = math.log(last_min_gas_price)*-200
        _integral = _last_integral + Ki * error * num_seconds_between_points
        _integral = clamp(_integral, (None, -1))  # avoid integral windup

        _derivative = -Kd * d_txpd / num_seconds_between_points

        # compute final output
        output = _proportional + _integral + _derivative
        output = clamp(output, output_limits)

        # This must be the inverse of _last_integral's calculation for it to work.
        result = math.exp(output/-200)

        return result


    def initialize_historical_minimum_gas_price_at_genesis(self, min_gas_price: int, net_tpc_cap: int) -> None:
        # we need to initialize the entire additive and fast sync region in time because that is where we check
        # that blocks have enough gas
        current_centisecond = int(time.time()/100) * 100

        historical_minimum_gas_price = []
        historical_tpc_capability = []
        for timestamp in range(current_centisecond-100*50, current_centisecond+100, 100):
            historical_minimum_gas_price.append([timestamp,min_gas_price])
            historical_tpc_capability.append([timestamp,net_tpc_cap])

        self.save_historical_minimum_gas_price(historical_minimum_gas_price)
        self.save_historical_network_tpc_capability(historical_tpc_capability, de_sparse = False)


    def get_required_block_min_gas_price(self) -> int:
        '''
        This has now changed. The required minimum gas price doesnt depend on the block time anymore. It depends
        on the instantaneous load on this node.
        '''

        hist_min_gas_price = self.load_historical_minimum_gas_price()

        if hist_min_gas_price is None or len(hist_min_gas_price) == 0:
            return 1

        return hist_min_gas_price[-1][1]


    def min_gas_system_initialization_required(self) -> bool:
        test_1 = self.load_historical_minimum_gas_price()
        test_3 = self.load_historical_network_tpc_capability()

        if test_1 is None or test_3 is None:
            return True

        return False

