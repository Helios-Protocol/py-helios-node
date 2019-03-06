import pathlib


class BaseHeliosError(Exception):
    """
    The base class for all Helios errors.
    """
    pass



class AmbigiousFileSystem(BaseHeliosError):
    """
    Raised when the file system paths are unclear
    """
    pass


class MissingPath(BaseHeliosError):
    """
    Raised when an expected path is missing
    """
    def __init__(self, msg: str, path: pathlib.Path) -> None:
        super().__init__(msg)
        self.path = path


class AlreadyWaiting(BaseHeliosError):
    """
    Raised when an attempt is made to wait for a certain message type from a
    peer when there is already an active wait for that message type.
    """
    pass


class SyncRequestAlreadyProcessed(BaseHeliosError):
    """
    Raised when a trie SyncRequest has already been processed.
    """
    pass


class OversizeObject(BaseHeliosError):
    """
    Raised when an object is bigger than comfortably fits in memory.
    """
    pass


class DAOForkCheckFailure(BaseHeliosError):
    """
    Raised when the DAO fork check with a certain peer is unsuccessful.
    """
    pass

class NoCandidatePeers(BaseHeliosError):
    """
    Raised when there are no peers to send a request to
    """
    pass

class SyncingError(BaseHeliosError):
    """
    Raised when there is an error while syncing
    """
    pass

class BaseRPCError(BaseHeliosError):
    """
    The base class for all RPC errors.
    """
    pass

