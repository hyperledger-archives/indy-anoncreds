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
    async def submitPrimaryClaim(self, id: ID, claim: PrimaryClaim):
        raise NotImplementedError

    @abstractmethod
    async def submitNonRevocClaim(self, id: ID, claim: NonRevocationClaim):
        raise NotImplementedError

    @abstractmethod
    async def submitMasterSecret(self, ms, id: ID):
        raise NotImplementedError

    @abstractmethod
    async def submitPrimaryClaimInitData(self, id: ID,
                                         claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    async def submitNonRevocClaimInitData(self, id: ID,
                                          claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    async def submitContextAttr(self, id: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    async def getMasterSecret(self, id: ID):
        raise NotImplementedError

    @abstractmethod
    async def getClaims(self, id: ID) -> Claims:
        raise NotImplementedError

    @abstractmethod
    async def getAllClaims(self) -> Dict[ClaimDefinitionKey, Claims]:
        raise NotImplementedError

    @abstractmethod
    async def getPrimaryClaimInitData(self, id: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    async def getNonRevocClaimInitData(self, id: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    async def getContextAttr(self, id: ID):
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

    async def submitPrimaryClaim(self, id: ID, claim: PrimaryClaim):
        await self._cacheValueForId(self._c1s, id, claim)

    async def submitNonRevocClaim(self, id: ID, claim: NonRevocationClaim):
        await self._cacheValueForId(self._c2s, id, claim)

    async def submitMasterSecret(self, ms, id: ID):
        await self._cacheValueForId(self._m1s, id, ms)

    async def submitPrimaryClaimInitData(self, id: ID,
                                         claimInitData: ClaimInitDataType):
        await self._cacheValueForId(self._primaryInitData, id, claimInitData)

    async def submitNonRevocClaimInitData(self, id: ID,
                                          claimInitData: ClaimInitDataType):
        await self._cacheValueForId(self._nonRevocInitData, id, claimInitData)

    async def submitContextAttr(self, id: ID, m2):
        await self._cacheValueForId(self._m2s, id, m2)

    # GET

    async def getMasterSecret(self, id: ID):
        return await self._getValueForId(self._m1s, id)

    async def getClaims(self, id: ID) -> Claims:
        c1 = await self._getValueForId(self._c1s, id)
        c2 = None if not self._c2s else await self._getValueForId(self._c2s, id)
        return Claims(c1, c2)

    async def getAllClaims(self) -> Dict[ClaimDefinitionKey, Claims]:
        res = {}
        for claimDefKey in self._c1s.keys():
            res[claimDefKey] = await self.getClaims(ID(claimDefKey))
        return res

    async def getPrimaryClaimInitData(self, id: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._primaryInitData, id)

    async def getNonRevocClaimInitData(self, id: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._nonRevocInitData, id)

    async def getContextAttr(self, id: ID):
        return await self._getValueForId(self._m2s, id)
