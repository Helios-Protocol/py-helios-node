from hvm.db.backends.base import BaseDB


class ReadOnlyDB(BaseDB):
    """
    Read only db. Stores changes in a temporary dictionary that is not written to the harddrive
    """

    def __init__(self, wrapped_db: BaseDB) -> None:
        self.wrapped_db = wrapped_db
        self.temp_db = {}

    def set(self, key: bytes, value: bytes) -> None:
        self.temp_db[key] = value

    def delete(self, key: bytes) -> None:
        self.set(key, 'deleted')

    def __getitem__(self, key: bytes) -> bytes:
        if key in self.temp_db and self.temp_db[key] == 'deleted':
            raise KeyError()
        try:
            return self.temp_db[key]
        except KeyError:
            return self.wrapped_db[key]

    def __setitem__(self, key: bytes, value: bytes) -> None:
        self.set(key, value)

    def _exists(self, key: bytes) -> bool:
        if key in self.temp_db and self.temp_db[key] == 'deleted':
            return False

        return key in self.wrapped_db or key in self.temp_db

    def __delitem__(self, key: bytes) -> None:
        self.delete(key)

    def atomic_batch(self):
        pass

    def destroy_db(self):
        pass

