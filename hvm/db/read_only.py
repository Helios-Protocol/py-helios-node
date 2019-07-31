from hvm.db.journal import JournalDB


class ReadOnlyDB(JournalDB):
    """
    Read only db. Stores changes in a temporary dictionary that is not written to the harddrive
    """

    def commit(self, changeset_id) -> None:
        pass
