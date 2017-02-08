from abc import abstractmethod
from typing import Dict, Any

from anoncreds.protocol.types import ID, PublicKey, RevocationPublicKey, \
    Schema, TailsType, Accumulator, \
    AccumulatorPublicKey, TimestampType, SchemaKey


class PublicRepo:
    # GET

    @abstractmethod
    async def getClaimDef(self, claimDefId: ID) -> Schema:
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
    async def getTails(self, claimDefId: ID) -> TailsType:
        raise NotImplementedError

    # SUBMIT

    @abstractmethod
    async def submitClaimDef(self,
                             claimDef: Schema) -> Schema:
        raise NotImplementedError

    @abstractmethod
    async def submitPublicKeys(self, claimDefId: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumulator(self, claimDefId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator, tails: TailsType) -> \
            AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def submitAccumUpdate(self, claimDefId: ID, accum: Accumulator,
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

    async def getClaimDef(self, claimDefId: ID) -> Schema:
        if claimDefId.claimDefKey and claimDefId.claimDefKey in self._claimDefsByKey:
            return self._claimDefsByKey[claimDefId.claimDefKey]

        if claimDefId.claimDefId and claimDefId.claimDefId in self._claimDefsById:
            return self._claimDefsById[claimDefId.claimDefId]

        raise KeyError(
            'No claim definition with ID={} and key={}'.format(
                claimDefId.claimDefId,
                claimDefId.claimDefKey))

    async def getPublicKey(self, claimDefId: ID) -> PublicKey:
        return await self._getValueForId(self._pks, claimDefId)

    async def getPublicKeyRevocation(self,
                                     claimDefId: ID) -> RevocationPublicKey:
        return await self._getValueForId(self._pkRs, claimDefId)

    async def getPublicKeyAccumulator(self,
                                      claimDefId: ID) -> AccumulatorPublicKey:
        return await self._getValueForId(self._accumPks, claimDefId)

    async def getAccumulator(self, claimDefId: ID) -> Accumulator:
        return await self._getValueForId(self._accums, claimDefId)

    async def getTails(self, claimDefId: ID) -> TailsType:
        return await self._getValueForId(self._tails, claimDefId)

    # SUBMIT

    async def submitClaimDef(self,
                             claimDef: Schema) -> Schema:
        claimDef = claimDef._replace(seqId=self._claimDefId)
        self._claimDefId += 1
        self._claimDefsByKey[claimDef.getKey()] = claimDef
        self._claimDefsById[claimDef.seqId] = claimDef
        return claimDef

    async def submitPublicKeys(self, claimDefId: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        pk = pk._replace(seqId=self._pkId)
        self._pkId += 1
        await self._cacheValueForId(self._pks, claimDefId, pk)

        if pkR:
            pkR = pkR._replace(seqId=self._pkRId)
            self._pkRId += 1
            await self._cacheValueForId(self._pkRs, claimDefId, pkR)

        return pk, pkR

    async def submitAccumulator(self, claimDefId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator,
                                tails: TailsType) -> AccumulatorPublicKey:
        accumPK = accumPK._replace(seqId=self._acumPkId)
        self._acumPkId += 1
        await self._cacheValueForId(self._accums, claimDefId, accum)
        accumPk = await self._cacheValueForId(self._accumPks, claimDefId,
                                              accumPK)
        await self._cacheValueForId(self._tails, claimDefId, tails)
        return accumPk

    async def submitAccumUpdate(self, claimDefId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        await self._cacheValueForId(self._accums, claimDefId, accum)

    async def _getValueForId(self, dictionary: Dict[SchemaKey, Any],
                             claimDefId: ID) -> Any:
        claimDef = await self.getClaimDef(claimDefId)
        claimDefKey = claimDef.getKey()
        if not claimDefKey in dictionary:
            raise ValueError(
                'No value for claim definition with ID={} and key={}'.format(
                    id.claimDefId, id.claimDefKey))
        return dictionary[claimDefKey]

    async def _cacheValueForId(self, dictionary: Dict[SchemaKey, Any],
                               claimDefId: ID, value: Any):
        claimDef = await self.getClaimDef(claimDefId)
        claimDefKey = claimDef.getKey()
        dictionary[claimDefKey] = value
