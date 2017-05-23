from abc import abstractmethod

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import Schema, PublicKey, SecretKey, ID, \
    RevocationPublicKey, AccumulatorPublicKey, Accumulator, Tails, \
    RevocationSecretKey, AccumulatorSecretKey, \
    TimestampType
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class IssuerWallet(Wallet):
    def __init__(self, schemaId, repo: PublicRepo):
        Wallet.__init__(self, schemaId, repo)

    # SUBMIT

    @abstractmethod
    async def submitSchema(self,
                           schema: Schema) -> Schema:
        raise NotImplementedError

    @abstractmethod
    async def submitPublicKeys(self, schemaId: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        raise NotImplementedError

    @abstractmethod
    async def submitSecretKeys(self, schemaId: ID, sk: SecretKey,
                               skR: RevocationSecretKey = None):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumPublic(self, schemaId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator, tails: Tails):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumSecret(self, schemaId: ID,
                                accumSK: AccumulatorSecretKey):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumUpdate(self, schemaId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        raise NotImplementedError

    @abstractmethod
    async def submitContextAttr(self, schemaId: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    async def getSecretKey(self, schemaId: ID) -> SecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getSecretKeyRevocation(self,
                                     schemaId: ID) -> RevocationSecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getSecretKeyAccumulator(self,
                                      schemaId: ID) -> AccumulatorSecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getContextAttr(self, schemaId: ID):
        raise NotImplementedError


class IssuerWalletInMemory(IssuerWallet, WalletInMemory):
    def __init__(self, schemaId, repo: PublicRepo):
        WalletInMemory.__init__(self, schemaId, repo)

        # other dicts with key=schemaKey
        self._sks = {}
        self._skRs = {}
        self._accumSks = {}
        self._m2s = {}
        self._attributes = {}

    # SUBMIT

    async def submitSchema(self,
                           schema: Schema) -> Schema:
        schema = await self._repo.submitSchema(schema)
        if schema:
            self._cacheSchema(schema)
        return schema

    async def submitPublicKeys(self, schemaId: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        pk, pkR = await self._repo.submitPublicKeys(schemaId, pk, pkR)
        await self._cacheValueForId(self._pks, schemaId, pk)
        if pkR:
            await  self._cacheValueForId(self._pkRs, schemaId, pkR)
        return pk, pkR

    async def submitSecretKeys(self, schemaId: ID, sk: SecretKey,
                               skR: RevocationSecretKey = None):
        await  self._cacheValueForId(self._sks, schemaId, sk)
        if skR:
            await  self._cacheValueForId(self._skRs, schemaId, skR)

    async def submitAccumPublic(self, schemaId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator,
                                tails: Tails) -> AccumulatorPublicKey:
        accumPK = await self._repo.submitAccumulator(schemaId, accumPK, accum,
                                                     tails)
        await self._cacheValueForId(self._accums, schemaId, accum)
        await self._cacheValueForId(self._accumPks, schemaId, accumPK)
        await self._cacheValueForId(self._tails, schemaId, tails)
        return accumPK

    async def submitAccumSecret(self, schemaId: ID,
                                accumSK: AccumulatorSecretKey):
        await self._cacheValueForId(self._accumSks, schemaId, accumSK)

    async def submitAccumUpdate(self, schemaId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        await self._repo.submitAccumUpdate(schemaId, accum, timestampMs)
        await self._cacheValueForId(self._accums, schemaId, accum)

    async def submitContextAttr(self, schemaId: ID, m2):
        await self._cacheValueForId(self._m2s, schemaId, m2)

    # GET

    async def getSecretKey(self, schemaId: ID) -> SecretKey:
        return await self._getValueForId(self._sks, schemaId)

    async def getSecretKeyRevocation(self,
                                     schemaId: ID) -> RevocationSecretKey:
        return await self._getValueForId(self._skRs, schemaId)

    async def getSecretKeyAccumulator(self,
                                      schemaId: ID) -> AccumulatorSecretKey:
        return await self._getValueForId(self._accumSks, schemaId)

    async def getContextAttr(self, schemaId: ID):
        return await self._getValueForId(self._m2s, schemaId)
