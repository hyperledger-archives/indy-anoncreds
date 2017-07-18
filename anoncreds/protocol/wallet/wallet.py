from abc import abstractmethod
from typing import Any, Dict, Sequence

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import Schema, SchemaKey, \
    PublicKey, ID, \
    RevocationPublicKey, AccumulatorPublicKey, Accumulator, Tails


class Wallet:
    def __init__(self, schemaId, repo: PublicRepo):
        self.walletId = schemaId
        self._repo = repo

    @property
    def name(self):
        return self.walletId

    # GET

    @abstractmethod
    async def getSchema(self, schemaId: ID) -> Schema:
        raise NotImplementedError

    @abstractmethod
    async def getAllSchemas(self) -> Sequence[Schema]:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKey(self, schemaId: ID) -> PublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyRevocation(self,
                                     schemaId: ID) -> RevocationPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getPublicKeyAccumulator(self,
                                      schemaId: ID) -> AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    async def getAccumulator(self, schemaId: ID) -> Accumulator:
        raise NotImplementedError

    @abstractmethod
    async def updateAccumulator(self, schemaId: ID, ts=None, seqNo=None):
        raise NotImplementedError

    @abstractmethod
    async def shouldUpdateAccumulator(self, schemaId: ID, ts=None,
                                      seqNo=None):
        raise NotImplementedError

    @abstractmethod
    async def getTails(self, schemaId: ID) -> Tails:
        raise NotImplementedError


class WalletInMemory(Wallet):
    def __init__(self, schemaId, repo: PublicRepo):
        Wallet.__init__(self, schemaId, repo)

        # schema dicts
        self._schemasByKey = {}
        self._schemasById = {}

        # other dicts with key=schemaKey
        self._pks = {}
        self._pkRs = {}
        self._accums = {}
        self._accumPks = {}
        self._tails = {}

    # GET

    async def getSchema(self, schemaId: ID) -> Schema:
        if schemaId.schemaKey and schemaId.schemaKey in self._schemasByKey:
            return self._schemasByKey[schemaId.schemaKey]
        if schemaId.schemaId and schemaId.schemaId in self._schemasById:
            return self._schemasById[schemaId.schemaId]

        schema = await self._repo.getSchema(schemaId)
        if not schema:
            raise ValueError('No schema with ID={} and key={}'.format(
                schemaId.schemaId, schemaId.schemaKey))

        self._cacheSchema(schema)

        return schema

    async def getAllSchemas(self) -> Sequence[Schema]:
        return self._schemasByKey.values()

    async def getPublicKey(self, schemaId: ID) -> PublicKey:
        return await self._getValueForId(self._pks, schemaId,
                                         self._repo.getPublicKey)

    async def getPublicKeyRevocation(self,
                                     schemaId: ID) -> RevocationPublicKey:
        return await self._getValueForId(self._pkRs, schemaId,
                                         self._repo.getPublicKeyRevocation)

    async def getPublicKeyAccumulator(self,
                                      schemaId: ID) -> AccumulatorPublicKey:
        return await self._getValueForId(self._accumPks, schemaId,
                                         self._repo.getPublicKeyAccumulator)

    async def getAccumulator(self, schemaId: ID) -> Accumulator:
        return await self._getValueForId(self._accums, schemaId,
                                         self._repo.getAccumulator)

    async def getTails(self, schemaId: ID) -> Tails:
        return await self._getValueForId(self._tails, schemaId,
                                         self._repo.getTails)

    async def updateAccumulator(self, schemaId: ID, ts=None, seqNo=None):
        acc = await self._repo.getAccumulator(schemaId)
        await self._cacheValueForId(self._accums, schemaId, acc)

    async def shouldUpdateAccumulator(self, schemaId: ID, ts=None,
                                      seqNo=None):
        # TODO
        return True

    # HELPER

    async def _getValueForId(self, dictionary: Dict[SchemaKey, Any],
                             schemaId: ID,
                             getFromRepo=None) -> Any:
        schema = await self.getSchema(schemaId)
        schemaKey = schema.getKey()

        if schemaKey in dictionary:
            return dictionary[schemaKey]

        value = None
        if getFromRepo:
            schemaId = schemaId._replace(schemaKey=schemaKey,
                                         schemaId=schema.seqId)
            value = await getFromRepo(schemaId)

        if not value:
            raise ValueError(
                'No value for schema with ID={} and key={}'.format(
                    schemaId.schemaId, schemaId.schemaKey))

        dictionary[schemaKey] = value
        return value

    async def _cacheValueForId(self, dictionary: Dict[SchemaKey, Any],
                               schemaId: ID, value: Any):
        schema = await self.getSchema(schemaId)
        schemaKey = schema.getKey()
        dictionary[schemaKey] = value

    def _cacheSchema(self, schema: Schema):
        self._schemasByKey[schema.getKey()] = schema
        if schema.seqId:
            self._schemasById[schema.seqId] = schema
