from abc import abstractmethod

from anoncreds.protocol.issuer_secret_key import IssuerSecretKey


class IssuerSecretKeyStore:
    """
    A private Issuer Secret Key store. Should be secured, encrypted, etc.
    """
    @abstractmethod
    def put(self, isk: IssuerSecretKey):
        pass

    @abstractmethod
    def get(self, cduid) -> IssuerSecretKey:
        pass
