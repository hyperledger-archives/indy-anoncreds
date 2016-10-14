from typing import Any
from typing import Dict

from anoncreds.protocol.exception import NotFoundError
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.issuer_key_store import IssuerKeyStore


class MemoryIssuerKeyStore(IssuerKeyStore):
    def __init__(self):
        self.byUid = {}  # type: Dict[Any, IssuerKey]

    def publishIssuerKey(self, ik: IssuerKey):
        self.byUid[ik.uid] = ik

    def fetchIssuerKey(self, uid) -> IssuerKey:
        try:
            return self.byUid[uid]
        except KeyError as ex:
            raise NotFoundError from ex
