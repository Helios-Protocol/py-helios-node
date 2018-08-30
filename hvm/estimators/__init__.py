import os
from typing import Callable

from hvm.utils.module_loading import (
    import_string,
)


def get_gas_estimator() -> Callable:
    import_path = os.environ.get(
        'GAS_ESTIMATOR_BACKEND_FUNC',
        'hvm.estimators.gas.binary_gas_search_intrinsic_tolerance',
    )
    return import_string(import_path)
