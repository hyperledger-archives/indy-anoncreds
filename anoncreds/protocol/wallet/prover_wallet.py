from abc import abstractmethod
from typing import Dict

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import ClaimDefinitionKey, ID, \
    Claims, ClaimInitDataType, \
    PrimaryClaim, NonRevocationClaim
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class ProverWallet(Wallet):
    def __init__(self, id, repo: PublicRepo):
        Wallet.__init__(self, id, repo)

    # SUBMIT

    @abstractmethod
    def submitPrimaryClaim(self, id: ID, claim: PrimaryClaim):
        raise NotImplementedError

    @abstractmethod
    def submitNonRevocClaim(self, id: ID, claim: NonRevocationClaim):
        raise NotImplementedError

    @abstractmethod
    def submitMasterSecret(self, ms, id: ID):
        raise NotImplementedError

    @abstractmethod
    def submitPrimaryClaimInitData(self, id: ID, claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    def submitNonRevocClaimInitData(self, id: ID, claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    def submitContextAttr(self, id: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    def getMasterSecret(self, id: ID):
        raise NotImplementedError

    @abstractmethod
    def getClaims(self, id: ID) -> Claims:
        raise NotImplementedError

    @abstractmethod
    def getAllClaims(self) -> Dict[ClaimDefinitionKey, Claims]:
        raise NotImplementedError

    @abstractmethod
    def getPrimaryClaimInitData(self, id: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    def getNonRevocClaimInitData(self, id: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    def getContextAttr(self, id: ID):
        raise NotImplementedError


class ProverWalletInMemory(ProverWallet, WalletInMemory):
    def __init__(self, id, repo: PublicRepo):
        WalletInMemory.__init__(self, id, repo)

        # other dicts with key=claimDefKey
        self._m1s = {}
        self._m2s = {}

        self._c1s = {}
        self._c2s = {}

        self._primaryInitData = {}
        self._nonRevocInitData = {}

    # SUBMIT

    def submitPrimaryClaim(self, id: ID, claim: PrimaryClaim):
        self._cacheValueForId(self._c1s, id, claim)

    def submitNonRevocClaim(self, id: ID, claim: NonRevocationClaim):
        self._cacheValueForId(self._c2s, id, claim)

    def submitMasterSecret(self, ms, id: ID):
        self._cacheValueForId(self._m1s, id, ms)

    def submitPrimaryClaimInitData(self, id: ID, claimInitData: ClaimInitDataType):
        self._cacheValueForId(self._primaryInitData, id, claimInitData)

    def submitNonRevocClaimInitData(self, id: ID, claimInitData: ClaimInitDataType):
        self._cacheValueForId(self._nonRevocInitData, id, claimInitData)

    def submitContextAttr(self, id: ID, m2):
        self._cacheValueForId(self._m2s, id, m2)

    # GET

    def getMasterSecret(self, id: ID):
        return self._getValueForId(self._m1s, id)

    def getClaims(self, id: ID) -> Claims:
        c1 = self._getValueForId(self._c1s, id)
        c2 = None if not self._c2s else self._getValueForId(self._c2s, id)
        return Claims(c1, c2)

    def getAllClaims(self) -> Dict[ClaimDefinitionKey, Claims]:
        return {claimDefKey: self.getClaims(ID(claimDefKey)) for claimDefKey in self._c1s.keys()}

    def getPrimaryClaimInitData(self, id: ID) -> ClaimInitDataType:
        return self._getValueForId(self._primaryInitData, id)

    def getNonRevocClaimInitData(self, id: ID) -> ClaimInitDataType:
        return self._getValueForId(self._nonRevocInitData, id)

    def getContextAttr(self, id: ID):
        return self._getValueForId(self._m2s, id)
