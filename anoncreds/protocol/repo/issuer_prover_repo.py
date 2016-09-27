from abc import abstractmethod
from typing import TypeVar, Generic

T = TypeVar('T')


class IssuerProverRepo(Generic[T]):
    @abstractmethod
    def addValue(self, issuerId, proverId, value: T):
        raise NotImplementedError

    @abstractmethod
    def getValue(self, issuerId, proverId) -> T:
        raise NotImplementedError


class InMemoryIssuerProverRepo(Generic[T]):
    def __init__(self):
        self.values = {}

    @abstractmethod
    def addValue(self, issuerId, proverId, value: T):
        self.values[(issuerId, proverId)] = value

    @abstractmethod
    def getValue(self, issuerId, proverId) -> T:
        return self.values[(issuerId, proverId)]
