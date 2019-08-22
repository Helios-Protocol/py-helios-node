import threading

import socket
import json

try:
    from json import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

from eth_utils import (
    to_text,
)

BUFSIZE = 4096

class BackendError(Exception):
    pass


from web3.providers.ipc import PersistantSocket, has_valid_json_rpc_ending
import pathlib
from web3._utils.threads import Timeout

class BaseProxy:

    def __init__(self, ipc_path):

        if isinstance(ipc_path, pathlib.Path):
            ipc_path = str(ipc_path.resolve())
        self.ipc_path = ipc_path

        self.ipc_timeout = 60*10

        self._lock = threading.Lock()

        self._socket = PersistantSocket(self.ipc_path)

    def process(self, request):
        with self._lock, self._socket as sock:
            try:
                sock.sendall(request)
            except BrokenPipeError:
                # one extra attempt, then give up
                sock = self._socket.reset()
                sock.sendall(request)

            raw_response = b''
            with Timeout(self.ipc_timeout) as timeout:
                while True:
                    try:
                        raw_response += sock.recv(BUFSIZE)
                    except socket.timeout:
                        timeout.sleep(0)
                        continue

                    if raw_response == b"":
                        timeout.sleep(0)
                    elif has_valid_json_rpc_ending(raw_response):
                        try:
                            json.loads(to_text(raw_response))
                        except JSONDecodeError:
                            timeout.sleep(0)
                            continue
                        else:
                            return raw_response
                    else:
                        timeout.sleep(0)
                        continue

                return response




