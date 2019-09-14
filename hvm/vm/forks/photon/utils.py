from hvm.utils.rlp import ensure_rlp_objects_are_equal, ensure_rlp_objects_are_equal_except_for_field_names
from hvm.vm.forks.boson.utils import boson_collect_touched_accounts

def photon_collect_touched_accounts(computation):
    return boson_collect_touched_accounts(computation)

ensure_computation_call_send_transactions_are_equal = ensure_rlp_objects_are_equal_except_for_field_names(
    obj_a_name="block transaction",
    obj_b_name="generated transaction",
    allowed_fields = {'v','r','s'}
)