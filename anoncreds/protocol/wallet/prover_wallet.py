from abc import abstractmethod
from typing import Dict

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import SchemaKey, ID, \
    Claims, ClaimInitDataType, \
    PrimaryClaim, NonRevocationClaim
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class ProverWallet(Wallet):
    def __init__(self, claimDefId, repo: PublicRepo):
        Wallet.__init__(self, claimDefId, repo)

    # SUBMIT

    @abstractmethod
    async def submitPrimaryClaim(self, claimDefId: ID, claim: PrimaryClaim):
        raise NotImplementedError

    @abstractmethod
    async def submitNonRevocClaim(self, claimDefId: ID,
                                  claim: NonRevocationClaim):
        raise NotImplementedError

    @abstractmethod
    async def submitMasterSecret(self, ms, claimDefId: ID):
        raise NotImplementedError

    @abstractmethod
    async def submitPrimaryClaimInitData(self, claimDefId: ID,
                                         claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    async def submitNonRevocClaimInitData(self, claimDefId: ID,
                                          claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    async def submitContextAttr(self, claimDefId: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    async def getMasterSecret(self, claimDefId: ID):
        raise NotImplementedError

    @abstractmethod
    async def getClaims(self, claimDefId: ID) -> Claims:
        raise NotImplementedError

    @abstractmethod
    async def getAllClaims(self) -> Dict[SchemaKey, Claims]:
        raise NotImplementedError

    @abstractmethod
    async def getPrimaryClaimInitData(self,
                                      claimDefId: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    async def getNonRevocClaimInitData(self,
                                       claimDefId: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    async def getContextAttr(self, claimDefId: ID):
        raise NotImplementedError


class ProverWalletInMemory(ProverWallet, WalletInMemory):
    def __init__(self, claimDefId, repo: PublicRepo):
        WalletInMemory.__init__(self, claimDefId, repo)

        # other dicts with key=claimDefKey
        self._m1s = {}
        self._m2s = {}

        self._c1s = {}
        self._c2s = {}

        self._primaryInitData = {}
        self._nonRevocInitData = {}

    # SUBMIT

    async def submitPrimaryClaim(self, claimDefId: ID, claim: PrimaryClaim):
        await self._cacheValueForId(self._c1s, claimDefId, claim)

    async def submitNonRevocClaim(self, claimDefId: ID,
                                  claim: NonRevocationClaim):
        await self._cacheValueForId(self._c2s, claimDefId, claim)

    async def submitMasterSecret(self, ms, claimDefId: ID):
        await self._cacheValueForId(self._m1s, claimDefId, ms)

    async def submitPrimaryClaimInitData(self, claimDefId: ID,
                                         claimInitData: ClaimInitDataType):
        await self._cacheValueForId(self._primaryInitData, claimDefId,
                                    claimInitData)

    async def submitNonRevocClaimInitData(self, claimDefId: ID,
                                          claimInitData: ClaimInitDataType):
        await self._cacheValueForId(self._nonRevocInitData, claimDefId,
                                    claimInitData)

    async def submitContextAttr(self, claimDefId: ID, m2):
        await self._cacheValueForId(self._m2s, claimDefId, m2)

    # GET

    async def getMasterSecret(self, claimDefId: ID):
        return await self._getValueForId(self._m1s, claimDefId)

    async def getClaims(self, claimDefId: ID) -> Claims:
        c1 = await self._getValueForId(self._c1s, claimDefId)
        c2 = None if not self._c2s else await self._getValueForId(self._c2s,
                                                                  claimDefId)
        return Claims(c1, c2)

    async def getAllClaims(self) -> Dict[SchemaKey, Claims]:
        res = {}
        for claimDefKey in self._c1s.keys():
            res[claimDefKey] = await self.getClaims(ID(claimDefKey))
        return res

    async def getPrimaryClaimInitData(self,
                                      claimDefId: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._primaryInitData, claimDefId)

    async def getNonRevocClaimInitData(self,
                                       claimDefId: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._nonRevocInitData, claimDefId)

    async def getContextAttr(self, claimDefId: ID):
        return await self._getValueForId(self._m2s, claimDefId)
