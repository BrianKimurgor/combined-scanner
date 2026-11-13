class UnsafeInputError(ValueError):
    """The submitted archive or repository was rejected; the message is safe to show the user."""


class UnsafeArchiveError(UnsafeInputError):
    pass


class UnsafeSourceError(UnsafeInputError):
    pass
