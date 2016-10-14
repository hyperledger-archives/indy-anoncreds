from typing import Any
from typing import Dict

from anoncreds.protocol.cred_def_store import CredDefStore
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.exception import NotFoundError


class MemoryCredDefStore(CredDefStore):
    def __init__(self):
        self.byUid = {}  # type: Dict[Any, CredentialDefinition]

    def publishCredDef(self, cd: CredentialDefinition):
        self.byUid[cd.uid] = cd

    def fetchCredDef(self, uid) -> CredentialDefinition:
        try:
            return self.byUid[uid]
        except KeyError as ex:
            raise NotFoundError("cred def id {}".format(uid)) from ex
