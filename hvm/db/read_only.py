from hvm.db.journal import JournalDB


class ReadOnlyDB(JournalDB):
    """
    Read only db. Stores changes in a temporary dictionary that is not written to the harddrive
    """

<<<<<<< HEAD
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
=======
    def commit(self, changeset_id) -> None:
>>>>>>> e6535648b79b577ad49c4f68ca4f637fbdb399bf
        pass
