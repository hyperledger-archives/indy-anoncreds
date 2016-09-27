from anoncreds.protocol.exception import NotFoundError
from anoncreds.protocol.issuer_secret_key import IssuerSecretKey
from anoncreds.protocol.issuer_secret_key_store import IssuerSecretKeyStore


class MemoryIssuerSecretKeyStore(IssuerSecretKeyStore):
    def __init__(self):
        self.secretKeys = {}  # Dict[cduid, IssuerSecretKey]

    def put(self, isk: IssuerSecretKey):
        self.secretKeys[isk.cd.uid] = isk

    def get(self, cduid) -> IssuerSecretKey:
        try:
            return self.secretKeys[cduid]
        except KeyError as ex:
            raise NotFoundError from ex
