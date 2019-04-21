from __future__ import absolute_import
from typing import Type  # noqa: F401

from hvm.db.account import (
    AccountDB,
)
from hvm.vm.forks.helios_testnet.state import HeliosTestnetTransactionExecutor, HeliosTestnetState


from .computation import BosonComputation

from .transaction_context import (
    BosonTransactionContext)


class BosonTransactionExecutor(HeliosTestnetTransactionExecutor):
    pass


class BosonState(HeliosTestnetState):
    computation_class: Type[BosonComputation] = BosonComputation
    transaction_executor: Type[BosonTransactionExecutor] = BosonTransactionExecutor
    account_db_class: Type[AccountDB] = AccountDB
    transaction_context_class: Type[BosonTransactionContext] = BosonTransactionContext
    
