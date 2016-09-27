from abc import abstractmethod
from typing import TypeVar, Generic

T = TypeVar('T')


class IssuerRepo(Generic[T]):
    @abstractmethod
    def addValue(self, issuerId, value: T):
        raise NotImplementedError

    @abstractmethod
    def getValue(self, issuerId) -> T:
        raise NotImplementedError


class InMemoryIssuerepo(Generic[T]):
    def __init__(self):
        self.values = {}

    @abstractmethod
    def addValue(self, issuerId, value: T):
        self.values[issuerId] = value

    @abstractmethod
    def getValue(self, issuerId) -> T:
        return self.values[issuerId]
