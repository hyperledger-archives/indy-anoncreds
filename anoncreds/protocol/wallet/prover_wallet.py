from abc import abstractmethod

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import ID, \
    Claims, ClaimInitDataType, \
    PrimaryClaim, NonRevocationClaim, ClaimsPair, ClaimAttributeValues
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory
from typing import Dict, Sequence, Any


class ProverWallet(Wallet):
    def __init__(self, schemaId, repo: PublicRepo):
        Wallet.__init__(self, schemaId, repo)

    # SUBMIT

    @abstractmethod
    async def submitClaimAttributes(
            self, schemaId: ID,
            claimAttributes: Dict[str, ClaimAttributeValues]):
        raise NotImplementedError

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
    async def getClaimAttributes(self, schemaId: ID):
        raise NotImplementedError

    @abstractmethod
    async def getAllClaimsAttributes(self) -> ClaimsPair:
        raise NotImplementedError

    @abstractmethod
    async def getClaimSignature(self, schemaId: ID) -> Claims:
        raise NotImplementedError

    @abstractmethod
    async def getAllClaimsSignatures(self):
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

        self._claims = {}

        # other dicts with key=schemaKey
        self._m1s = {}
        self._m2s = {}

        self._c1s = {}
        self._c2s = {}

        self._primaryInitData = {}
        self._nonRevocInitData = {}

    # SUBMIT

    async def submitClaimAttributes(
            self, schemaId: ID,
            claimAttributes: Dict[str, ClaimAttributeValues]):
        await self._cacheValueForId(self._claims, schemaId, claimAttributes)

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

    async def getClaimAttributes(self, schemaId: ID):
        return await self._getValueForId(self._claims, schemaId)

    async def getClaimSignature(self, schemaId: ID) -> Claims:
        c1 = await self._getValueForId(self._c1s, schemaId)
        c2 = None if not self._c2s else await self._getValueForId(self._c2s,
                                                                  schemaId)
        return Claims(c1, c2)

    async def getAllClaimsAttributes(self) -> ClaimsPair:
        res = ClaimsPair()
        for schemaKey in self._claims.keys():
            res[schemaKey] = await self.getClaimAttributes(ID(schemaKey))
        return res

    async def getAllClaimsSignatures(self):
        res = dict()
        for schemaKey in self._c1s.keys():
            res[schemaKey] = await self.getClaimSignature(ID(schemaKey))
        return res

    async def getPrimaryClaimInitData(self,
                                      schemaId: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._primaryInitData, schemaId)

    async def getNonRevocClaimInitData(self,
                                       schemaId: ID) -> ClaimInitDataType:
        return await self._getValueForId(self._nonRevocInitData, schemaId)

    async def getContextAttr(self, schemaId: ID):
        return await self._getValueForId(self._m2s, schemaId)
