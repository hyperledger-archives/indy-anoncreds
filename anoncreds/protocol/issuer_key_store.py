from abc import abstractmethod

from anoncreds.protocol.issuer_key import IssuerKey


class IssuerKeyStore:
    @abstractmethod
    def publish(self, cd: IssuerKey):
        pass

    @abstractmethod
    def fetch(self, uid) -> IssuerKey:
        pass
