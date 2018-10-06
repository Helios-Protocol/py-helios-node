# Release Process

1. Populate `docs/release_notes/helios.rst`
2. Release `py-evm`
3. Bump py-evm dependency version in `setup_helios.py`
4. Manual bump of helios version in `setup_helios.py`
5. Release `helios`
6. Tag helios release


## Environment Configuration

- `HELIOS_MP_CONTEXT` - The context that new processes will be spawned from the python `multiprocessing` library.
- `XDG_HELIOS_ROOT` - Base directory where helios stores data
- `HELIOS_DATA_DIR` - The root directory where the chain data will be stored for the currently running chain.
- `HELIOS_NODEKEY` - The path to a file where the devp2p private key is stored.
- `HELIOS_DATABASE_IPC` - The path to the socket which connects to the database manager.
