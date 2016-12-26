from abc import abstractmethod
from typing import Any, Dict, Sequence

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import ClaimDefinition, ClaimDefinitionKey, \
    PublicKey, ID, \
    RevocationPublicKey, AccumulatorPublicKey, Accumulator, TailsType


class Wallet:
    def __init__(self, claimDefId, repo: PublicRepo):
        self.walletId = claimDefId
        self._repo = repo

    # GET

    @abstractmethod
    async def getClaimDef(self, claimDefId: ID) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    async def getAllClaimDef(self) -> Sequence[ClaimDefinition]:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKey(self, claimDefId: ID) -> PublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyRevocation(self,
                                     claimDefId: ID) -> RevocationPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyAccumulator(self,
                                      claimDefId: ID) -> AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getAccumulator(self, claimDefId: ID) -> Accumulator:
        raise NotImplementedError

    @abstractmethod
    async def updateAccumulator(self, claimDefId: ID, ts=None, seqNo=None):
        raise NotImplementedError

    @abstractmethod
    async def shouldUpdateAccumulator(self, claimDefId: ID, ts=None,
                                      seqNo=None):
        raise NotImplementedError

    @abstractmethod
    async def getTails(self, claimDefId: ID) -> TailsType:
        raise NotImplementedError


class WalletInMemory(Wallet):
    def __init__(self, claimDefId, repo: PublicRepo):
        Wallet.__init__(self, claimDefId, repo)

        # claim def dicts
        self._claimDefsByKey = {}
        self._claimDefsById = {}

        # other dicts with key=claimDefKey
        self._pks = {}
        self._pkRs = {}
        self._accums = {}
        self._accumPks = {}
        self._tails = {}

    # GET

    async def getClaimDef(self, claimDefId: ID) -> ClaimDefinition:
        if claimDefId.claimDefKey and claimDefId.claimDefKey in self._claimDefsByKey:
            return self._claimDefsByKey[claimDefId.claimDefKey]
        if claimDefId.claimDefId and claimDefId.claimDefId in self._claimDefsById:
            return self._claimDefsById[claimDefId.claimDefId]

        claimDef = await self._repo.getClaimDef(claimDefId)
        if not claimDef:
            raise ValueError('No claim definition with ID={} and key={}'.format(
                claimDefId.claimDefId, claimDefId.claimDefKey))

        self._cacheClaimDef(claimDef)

        return claimDef

    async def getAllClaimDef(self) -> Sequence[ClaimDefinition]:
        return self._claimDefsByKey.values()

    async def getPublicKey(self, claimDefId: ID) -> PublicKey:
        return await self._getValueForId(self._pks, claimDefId,
                                         self._repo.getPublicKey)

    async def getPublicKeyRevocation(self,
                                     claimDefId: ID) -> RevocationPublicKey:
        return await self._getValueForId(self._pkRs, claimDefId,
                                         self._repo.getPublicKeyRevocation)

    async def getPublicKeyAccumulator(self,
                                      claimDefId: ID) -> AccumulatorPublicKey:
        return await self._getValueForId(self._accumPks, claimDefId,
                                         self._repo.getPublicKeyAccumulator)

    async def getAccumulator(self, claimDefId: ID) -> Accumulator:
        return await self._getValueForId(self._accums, claimDefId,
                                         self._repo.getAccumulator)

    async def getTails(self, claimDefId: ID) -> TailsType:
        return await self._getValueForId(self._tails, claimDefId,
                                         self._repo.getTails)

    async def updateAccumulator(self, claimDefId: ID, ts=None, seqNo=None):
        acc = await self._repo.getAccumulator(claimDefId)
        await self._cacheValueForId(self._accums, claimDefId, acc)

    async def shouldUpdateAccumulator(self, claimDefId: ID, ts=None,
                                      seqNo=None):
        # TODO
        return True

    # HELPER

    async def _getValueForId(self, dictionary: Dict[ClaimDefinitionKey, Any],
                             claimDefId: ID,
                             getFromRepo=None) -> Any:
        claimDef = await self.getClaimDef(claimDefId)
        claimDefKey = claimDef.getKey()

        if claimDefKey in dictionary:
            return dictionary[claimDefKey]

        value = None
        if getFromRepo:
            claimDefId = claimDefId._replace(claimDefKey=claimDefKey,
                                             claimDefId=claimDef.seqId)
            value = await getFromRepo(claimDefId)

        if not value:
            raise ValueError(
                'No value for claim definition with ID={} and key={}'.format(
                    claimDefId.claimDefId, claimDefId.claimDefKey))

        dictionary[claimDefKey] = value
        return value

    async def _cacheValueForId(self, dictionary: Dict[ClaimDefinitionKey, Any],
                               claimDefId: ID, value: Any):
        claimDef = await self.getClaimDef(claimDefId)
        claimDefKey = claimDef.getKey()
        dictionary[claimDefKey] = value

    def _cacheClaimDef(self, claimDef: ClaimDefinition):
        self._claimDefsByKey[claimDef.getKey()] = claimDef
        if claimDef.seqId:
            self._claimDefsById[claimDef.seqId] = claimDef
