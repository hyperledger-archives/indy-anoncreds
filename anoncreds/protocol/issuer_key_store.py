from abc import abstractmethod

from anoncreds.protocol.issuer_key import IssuerKey


class IssuerKeyStore:
    """
    A public issuer key store. Could be a public API, or a distributed ledger
    like Sovrin.
    """

    @abstractmethod
    def publish(self, cd: IssuerKey):
        pass

    @abstractmethod
    def fetch(self, uid) -> IssuerKey:
        pass
