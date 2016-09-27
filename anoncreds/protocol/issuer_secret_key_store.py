from abc import abstractmethod

from anoncreds.protocol.issuer_secret_key import IssuerSecretKey


class IssuerSecretKeyStore:
    @abstractmethod
    def put(self, isk: IssuerSecretKey):
        pass

    @abstractmethod
    def get(self, cduid) -> IssuerSecretKey:
        pass
