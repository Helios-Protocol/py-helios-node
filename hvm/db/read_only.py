from hvm.db.backends.base import BaseDB


class ReadOnlyDB(BaseDB):
    """
    Read only db
    """

    def __init__(self, wrapped_db: BaseDB) -> None:
        self.wrapped_db = wrapped_db

    def set(self, key: bytes, value: bytes) -> None:
        pass

    def delete(self, key: bytes) -> None:
        pass

    def __getitem__(self, key: bytes) -> bytes:
        return self.wrapped_db[key]

    def __setitem__(self, key: bytes, value: bytes) -> None:
        pass

    def _exists(self, key: bytes) -> bool:
        return key in self.wrapped_db

    def __delitem__(self, key: bytes) -> None:
        pass

    def atomic_batch(self):
        pass

    def destroy_db(self):
        pass