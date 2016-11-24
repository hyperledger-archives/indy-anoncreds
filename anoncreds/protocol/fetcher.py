from abc import abstractmethod

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.types import ID, Claims


class Fetcher:
    @abstractmethod
    def fetchClaims(self, userId, id: ID, U, Ur) -> (Claims, str):
        pass


class SimpleFetcher(Fetcher):
    def __init__(self, issuer: Issuer):
        self._issuer = issuer

    def fetchClaims(self, userId, id: ID, U, Ur) -> (Claims, str):
        return self._issuer.issueClaims(id, U, Ur, userId)
