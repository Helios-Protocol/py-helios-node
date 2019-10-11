import logging
from typing import (
    cast
)

from hvm.exceptions import (
    ValidationError,
    OutOfGas,
)
from hvm.validation import (
    validate_uint256,
)
from hvm.utils.logging import (
    TraceLogger
)
from typing import Callable

def default_refund_strategy(gas_refunded_total: int, amount: int) -> int:
    if amount < 0:
        raise ValidationError("Gas refund amount must be positive")

    return gas_refunded_total + amount


def allow_negative_refund_strategy(gas_refunded_total: int, amount: int) -> int:
    return gas_refunded_total + amount


RefundStrategy = Callable[[int, int], int]


class GasMeter(object):

    start_gas: int = None

    gas_refunded: int = None
    gas_remaining: int = None

    logger = cast(TraceLogger, logging.getLogger('hvm.gas.GasMeter'))

    def __init__(self,
                 start_gas: int,
                 refund_strategy: RefundStrategy = default_refund_strategy) -> None:
        validate_uint256(start_gas, title="Start Gas")

        self.refund_strategy = refund_strategy
        self.start_gas = start_gas

        self.gas_remaining = self.start_gas
        self.gas_refunded = 0

    #
    # Write API
    #
    def consume_gas(self, amount: int, reason: str) -> None:
        if amount < 0:
            raise ValidationError("Gas consumption amount must be positive")

        if amount > self.gas_remaining:
            raise OutOfGas("Out of gas: Needed {0} - Remaining {1} - Reason: {2}".format(
                amount,
                self.gas_remaining,
                reason,
            ))

        self.gas_remaining -= amount

        self.logger.trace(
            'GAS CONSUMPTION: %s - %s -> %s (%s)',
            self.gas_remaining + amount,
            amount,
            self.gas_remaining,
            reason,
        )

    def return_gas(self, amount: int) -> None:
        if amount < 0:
            raise ValidationError("Gas return amount must be positive")

        self.gas_remaining += amount

        self.logger.trace(
            'GAS RETURNED: %s + %s -> %s',
            self.gas_remaining - amount,
            amount,
            self.gas_remaining,
        )

    def refund_gas(self, amount: int) -> None:
        self.gas_refunded = self.refund_strategy(self.gas_refunded, amount)

        self.logger.trace(
            'GAS REFUND: %s + %s -> %s',
            self.gas_refunded - amount,
            amount,
            self.gas_refunded,
        )



# class GasMeter(object):
#     start_gas = None  # type: int
#
#     gas_refunded = None  # type: int
#     gas_remaining = None  # type: int
#
#     logger = cast(TraceLogger, logging.getLogger('hvm.gas.GasMeter'))
#
#     def __init__(self, start_gas: int) -> None:
#         validate_uint256(start_gas, title="Start Gas")
#
#         self.start_gas = start_gas
#
#         self.gas_remaining = self.start_gas
#         self.gas_refunded = 0
#
#     #
#     # Write API
#     #
#     def consume_gas(self, amount: int, reason: str) -> None:
#         if amount < 0:
#             raise ValidationError("Gas consumption amount must be positive")
#
#         if amount > self.gas_remaining:
#             raise OutOfGas("Out of gas: Needed {0} - Remaining {1} - Reason: {2}".format(
#                 amount,
#                 self.gas_remaining,
#                 reason,
#             ))
#
#         self.gas_remaining -= amount
#
#         self.logger.trace(
#             'GAS CONSUMPTION: %s - %s -> %s (%s)',
#             self.gas_remaining + amount,
#             amount,
#             self.gas_remaining,
#             reason,
#         )
#
#     def return_gas(self, amount: int) -> None:
#         if amount < 0:
#             raise ValidationError("Gas return amount must be positive")
#
#         self.gas_remaining += amount
#
#         self.logger.trace(
#             'GAS RETURNED: %s + %s -> %s',
#             self.gas_remaining - amount,
#             amount,
#             self.gas_remaining,
#         )
#
#     def refund_gas(self, amount: int) -> None:
#         if amount < 0:
#             raise ValidationError("Gas refund amount must be positive")
#
#         self.gas_refunded += amount
#
#         self.logger.trace(
#             'GAS REFUND: %s + %s -> %s',
#             self.gas_refunded - amount,
#             amount,
#             self.gas_refunded,
#         )
