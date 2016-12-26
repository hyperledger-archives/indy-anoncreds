from abc import abstractmethod
from typing import Dict, Any

from anoncreds.protocol.types import ID, PublicKey, RevocationPublicKey, \
    ClaimDefinition, TailsType, Accumulator, \
    AccumulatorPublicKey, TimestampType, ClaimDefinitionKey


class PublicRepo():
    # GET

    @abstractmethod
    async def getClaimDef(self, id: ID) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKey(self, id: ID) -> PublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyRevocation(self, id: ID) -> RevocationPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyAccumulator(self, id: ID) -> AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getAccumulator(self, id: ID) -> Accumulator:
        raise NotImplementedError

    @abstractmethod
    async def getTails(self, id: ID) -> TailsType:
        raise NotImplementedError

    # SUBMIT

    @abstractmethod
    async def submitClaimDef(self,
                             claimDef: ClaimDefinition) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    async def submitPublicKeys(self, id: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumulator(self, id: ID, accumPK: AccumulatorPublicKey,
                                accum: Accumulator, tails: TailsType) -> \
            AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def submitAccumUpdate(self, id: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        raise NotImplementedError


class PublicRepoInMemory(PublicRepo):
    def __init__(self):
        self._claimDefsByKey = {}
        self._claimDefsById = {}
        self._pks = {}
        self._pkRs = {}
        self._accums = {}
        self._accumPks = {}
        self._tails = {}
        self._claimDefId = 1
        self._pkId = 1
        self._pkRId = 1
        self._acumPkId = 1

    # GET

    async def getClaimDef(self, id: ID) -> ClaimDefinition:
        if id.claimDefKey and id.claimDefKey in self._claimDefsByKey:
            return self._claimDefsByKey[id.claimDefKey]

        if id.claimDefId and id.claimDefId in self._claimDefsById:
            return self._claimDefsById[id.claimDefId]

        raise ValueError(
            'No claim definition with ID={} and key={}'.format(id.claimDefId,
                                                               id.claimDefKey))

    async def getPublicKey(self, id: ID) -> PublicKey:
        return await self._getValueForId(self._pks, id)

    async def getPublicKeyRevocation(self, id: ID) -> RevocationPublicKey:
        return await self._getValueForId(self._pkRs, id)

    async def getPublicKeyAccumulator(self, id: ID) -> AccumulatorPublicKey:
        return await self._getValueForId(self._accumPks, id)

    async def getAccumulator(self, id: ID) -> Accumulator:
        return await self._getValueForId(self._accums, id)

    async def getTails(self, id: ID) -> TailsType:
        return await self._getValueForId(self._tails, id)

    # SUBMIT

    async def submitClaimDef(self,
                             claimDef: ClaimDefinition) -> ClaimDefinition:
        claimDef = claimDef._replace(id=self._claimDefId)
        self._claimDefId += 1
        self._claimDefsByKey[claimDef.getKey()] = claimDef
        self._claimDefsById[claimDef.id] = claimDef
        return claimDef

    async def submitPublicKeys(self, id: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        pk = pk._replace(id=self._pkId)
        self._pkId += 1
        await self._cacheValueForId(self._pks, id, pk)

        if pkR:
            pkR = pkR._replace(id=self._pkRId)
            self._pkRId += 1
            await self._cacheValueForId(self._pkRs, id, pkR)

        return (pk, pkR)

    async def submitAccumulator(self, id: ID, accumPK: AccumulatorPublicKey,
                                accum: Accumulator,
                                tails: TailsType) -> AccumulatorPublicKey:
        accumPK = accumPK._replace(id=self._acumPkId)
        self._acumPkId += 1
        await self._cacheValueForId(self._accums, id, accum)
        accumPk = await self._cacheValueForId(self._accumPks, id, accumPK)
        await self._cacheValueForId(self._tails, id, tails)
        return accumPk

    async def submitAccumUpdate(self, id: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        await self._cacheValueForId(self._accums, id, accum)

    async def _getValueForId(self, dict: Dict[ClaimDefinitionKey, Any],
                             id: ID) -> Any:
        claimDef = await self.getClaimDef(id)
        claimDefKey = claimDef.getKey()
        if not claimDefKey in dict:
            raise ValueError(
                'No value for claim definition with ID={} and key={}'.format(
                    id.claimDefId, id.claimDefKey))
        return dict[claimDefKey]

    async def _cacheValueForId(self, dict: Dict[ClaimDefinitionKey, Any],
                               id: ID, value: Any):
        claimDef = await self.getClaimDef(id)
        claimDefKey = claimDef.getKey()
        dict[claimDefKey] = value
