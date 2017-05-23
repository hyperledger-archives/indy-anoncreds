from abc import abstractmethod
from typing import Dict, Any

from anoncreds.protocol.types import ID, PublicKey, RevocationPublicKey, \
    Schema, Tails, Accumulator, \
    AccumulatorPublicKey, TimestampType, SchemaKey


class PublicRepo:
    # GET

    @abstractmethod
    async def getSchema(self, schemaId: ID) -> Schema:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKey(self,
                           schemaId: ID,
                           signatureType = 'CL') -> PublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyRevocation(self,
                                     schemaId: ID,
                                     signatureType = 'CL') -> RevocationPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyAccumulator(self,
                                      schemaId: ID) -> AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getAccumulator(self, schemaId: ID) -> Accumulator:
        raise NotImplementedError

    @abstractmethod
    async def getTails(self, schemaId: ID) -> Tails:
        raise NotImplementedError

    # SUBMIT

    @abstractmethod
    async def submitSchema(self,
                           schema: Schema) -> Schema:
        raise NotImplementedError

    @abstractmethod
    async def submitPublicKeys(self,
                               schemaId: ID,
                               pk: PublicKey,
                               pkR: RevocationPublicKey = None,
                               signatureType = 'CL') -> (
            PublicKey, RevocationPublicKey):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumulator(self, schemaId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator, tails: Tails) -> \
            AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def submitAccumUpdate(self, schemaId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        raise NotImplementedError


class PublicRepoInMemory(PublicRepo):
    def __init__(self):
        self._schemasByKey = {}
        self._schemasById = {}
        self._pks = {}
        self._pkRs = {}
        self._accums = {}
        self._accumPks = {}
        self._tails = {}
        self._schemaId = 1
        self._pkId = 1
        self._pkRId = 1
        self._acumPkId = 1

    # GET

    async def getSchema(self, schemaId: ID) -> Schema:
        if schemaId.schemaKey and schemaId.schemaKey in self._schemasByKey:
            return self._schemasByKey[schemaId.schemaKey]

        if schemaId.schemaId and schemaId.schemaId in self._schemasById:
            return self._schemasById[schemaId.schemaId]

        raise KeyError(
            'No schema with ID={} and key={}'.format(
                schemaId.schemaId,
                schemaId.schemaKey))

    async def getPublicKey(self,
                           schemaId: ID,
                           signatureType = 'CL') -> PublicKey:
        return await self._getValueForId(self._pks, schemaId)

    async def getPublicKeyRevocation(self,
                                     schemaId: ID,
                                     signatureType = 'CL') -> RevocationPublicKey:
        return await self._getValueForId(self._pkRs, schemaId)

    async def getPublicKeyAccumulator(self,
                                      schemaId: ID) -> AccumulatorPublicKey:
        return await self._getValueForId(self._accumPks, schemaId)

    async def getAccumulator(self, schemaId: ID) -> Accumulator:
        return await self._getValueForId(self._accums, schemaId)

    async def getTails(self, schemaId: ID) -> Tails:
        return await self._getValueForId(self._tails, schemaId)

    # SUBMIT

    async def submitSchema(self,
                           schema: Schema) -> Schema:
        schema = schema._replace(seqId=self._schemaId)
        self._schemaId += 1
        self._schemasByKey[schema.getKey()] = schema
        self._schemasById[schema.seqId] = schema
        return schema

    async def submitPublicKeys(self,
                               schemaId: ID,
                               pk: PublicKey,
                               pkR: RevocationPublicKey = None,
                               signatureType='CL') -> (
            PublicKey, RevocationPublicKey):
        pk = pk._replace(seqId=self._pkId)
        self._pkId += 1
        await self._cacheValueForId(self._pks, schemaId, pk)

        if pkR:
            pkR = pkR._replace(seqId=self._pkRId)
            self._pkRId += 1
            await self._cacheValueForId(self._pkRs, schemaId, pkR)

        return pk, pkR

    async def submitAccumulator(self, schemaId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator,
                                tails: Tails) -> AccumulatorPublicKey:
        accumPK = accumPK._replace(seqId=self._acumPkId)
        self._acumPkId += 1
        await self._cacheValueForId(self._accums, schemaId, accum)
        accumPk = await self._cacheValueForId(self._accumPks, schemaId,
                                              accumPK)
        await self._cacheValueForId(self._tails, schemaId, tails)
        return accumPk

    async def submitAccumUpdate(self, schemaId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        await self._cacheValueForId(self._accums, schemaId, accum)

    async def _getValueForId(self, dictionary: Dict[SchemaKey, Any],
                             schemaId: ID) -> Any:
        schema = await self.getSchema(schemaId)
        schemaKey = schema.getKey()
        if not schemaKey in dictionary:
            raise ValueError(
                'No value for schema with ID={} and key={}'.format(
                    schemaId.schemaId, schemaId.schemaKey))
        return dictionary[schemaKey]

    async def _cacheValueForId(self, dictionary: Dict[SchemaKey, Any],
                               schemaId: ID, value: Any):
        schema = await self.getSchema(schemaId)
        schemaKey = schema.getKey()
        dictionary[schemaKey] = value
