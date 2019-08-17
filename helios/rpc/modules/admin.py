
from helios.rpc.modules import (  # type: ignore
    RPCModule,
)
from helios.utils.verification import verify_rpc_admin_password

from hvm.exceptions import ValidationError
class Admin(RPCModule):


    async def stopRPC(self, password: str):
        if not verify_rpc_admin_password(password, self._rpc_context.admin_rpc_password_config_path):
            raise ValidationError("Incorrect password.")

        self._rpc_context.halt_rpc.set()

    async def startRPC(self, password: str):
        if not verify_rpc_admin_password(password, self._rpc_context.admin_rpc_password_config_path):
            raise ValidationError("Incorrect password.")

        self._rpc_context.halt_rpc.clear()

