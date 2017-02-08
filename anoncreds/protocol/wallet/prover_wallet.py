from abc import abstractmethod
from typing import Dict

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import SchemaKey, ID, \
    Claims, ClaimInitDataType, \
    PrimaryClaim, NonRevocationClaim
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class ProverWallet(Wallet):
    def __init__(self, schemaId, repo: PublicRepo):
        Wallet.__init__(self, schemaId, repo)

    # SUBMIT

    @abstractmethod
    async def submitPrimaryClaim(self, schemaId: ID, claim: PrimaryClaim):
        raise NotImplementedError

    @abstractmethod
    async def submitNonRevocClaim(self, schemaId: ID,
                                  claim: NonRevocationClaim):
        raise NotImplementedError

    @abstractmethod
    async def submitMasterSecret(self, ms, schemaId: ID):
        raise NotImplementedError

    @abstractmethod
    async def submitPrimaryClaimInitData(self, schemaId: ID,
                                         claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    async def submitNonRevocClaimInitData(self, schemaId: ID,
                                          claimInitData: ClaimInitDataType):
        raise NotImplementedError

    @abstractmethod
    async def submitContextAttr(self, schemaId: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    async def getMasterSecret(self, schemaId: ID):
        raise NotImplementedError

    @abstractmethod
    async def getClaims(self, schemaId: ID) -> Claims:
        raise NotImplementedError

    @abstractmethod
    async def getAllClaims(self) -> Dict[SchemaKey, Claims]:
        raise NotImplementedError

    @abstractmethod
    async def getPrimaryClaimInitData(self,
                                      schemaId: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    async def getNonRevocClaimInitData(self,
                                       schemaId: ID) -> ClaimInitDataType:
        raise NotImplementedError

    @abstractmethod
    async def getContextAttr(self, schemaId: ID):
        raise NotImplementedError


class ProverWalletInMemory(ProverWallet, WalletInMemory):
    def __init__(self, schemaId, repo: PublicRepo):
        WalletInMemory.__init__(self, schemaId, repo)

        # other dicts with key=schemaKey
        self._m1s = {}
        self._m2s = {}

        self._c1s = {}
        self._c2s = {}

        self._primaryInitData = {}
        self._nonRevocInitData = {}

    # SUBMIT

    async def submitPrimaryClaim(self, schemaId: ID, claim: PrimaryClaim):
        await self._cacheValueForId(self._c1s, schemaId, claim)

    async def submitNonRevocClaim(self, schemaId: ID,
                                  claim: NonRevocationClaim):
        await self._cacheValueForId(self._c2s, schemaId, claim)

    async def submitMasterSecret(self, ms, schemaId: ID):
        await self._cacheValueForId(self._m1s, schemaId, ms)

    async def submitPrimaryClaimInitData(self, schemaId: ID,
                                         claimInitData: ClaimInitDataType):
        await self._cacheValueForId(self._primaryInitData, schemaId,
                                    claimInitData)

    async def submitNonRevocClaimInitData(self, schemaId: ID,
                                          claimInitData: ClaimInitDataType):
        await self._cacheValueForId(self._nonRevocInitData, schemaId,
                                    claimInitData)

    async def submitContextAttr(self, schemaId: ID, m2):
        await self._cacheValueForId(self._m2s, schemaId, m2)

    # GET

    async def getMasterSecret(self, schemaId: ID):
        return await self._getValueForId(self._m1s, schemaId)

    async def getClaims(self, schemaId: ID) -> Claims:
        c1 = await self._getValueForId(self._c1s, schemaId)
        c2 = None if not self._c2s else await self._getValueForId(self._c2s,
                                                                  schemaId)
        return Claims(c1, c2)

    async def getAllClaims(self) -> Dict[SchemaKey, Claims]:
        res = {}
        for schemaKey in self._c1s.keys():
            res[schemaKey] = await self.getClaims(ID(schemaKey))
        return res

    async def getPrimaryClaimInitData(self,
                                      schemaId: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._primaryInitData, schemaId)

    async def getNonRevocClaimInitData(self,
                                       schemaId: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._nonRevocInitData, schemaId)

    async def getContextAttr(self, schemaId: ID):
        return await self._getValueForId(self._m2s, schemaId)
