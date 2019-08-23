from __future__ import absolute_import
from typing import Type  # noqa: F401

from .account import PhotonAccountDB
from hvm.vm.forks.boson.state import BosonTransactionExecutor, BosonState

from .computation import PhotonComputation

from .transaction_context import PhotonTransactionContext


class PhotonTransactionExecutor(BosonTransactionExecutor):
    pass


class PhotonState(BosonState):
    computation_class: Type[PhotonComputation] = PhotonComputation
    transaction_executor: Type[PhotonTransactionExecutor] = PhotonTransactionExecutor
    account_db_class: Type[PhotonAccountDB] = PhotonAccountDB
    transaction_context_class: Type[PhotonTransactionContext] = PhotonTransactionContext
    
