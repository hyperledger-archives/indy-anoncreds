from abc import abstractmethod
from typing import Dict, Any

from anoncreds.protocol.types import ID, PublicKey, RevocationPublicKey, ClaimDefinition, TailsType, Accumulator, \
    AccumulatorPublicKey, TimestampType, ClaimDefinitionKey


class PublicRepo():
    # GET

    @abstractmethod
    def getClaimDef(self, id: ID) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    def getPublicKey(self, id: ID) -> PublicKey:
        raise NotImplementedError

    @abstractmethod
    def getPublicKeyRevocation(self, id: ID) -> RevocationPublicKey:
        raise NotImplementedError

    @abstractmethod
    def getPublicKeyAccumulator(self, id: ID) -> AccumulatorPublicKey:
        raise NotImplementedError

    @abstractmethod
    def getAccumulator(self, id: ID) -> Accumulator:
        raise NotImplementedError

    @abstractmethod
    def getTails(self, id: ID) -> TailsType:
        raise NotImplementedError

    # SUBMIT

    @abstractmethod
    def submitClaimDef(self, claimDef: ClaimDefinition):
        raise NotImplementedError

    @abstractmethod
    def submitPublicKeys(self, id: ID, pk: PublicKey, pkR: RevocationPublicKey = None):
        raise NotImplementedError

    @abstractmethod
    def submitAccumulator(self, id: ID, accumPK: AccumulatorPublicKey, accum: Accumulator, tails: TailsType):
        raise NotImplementedError

    @abstractmethod
    def submitAccumUpdate(self, id: ID, accum: Accumulator, timestampMs: TimestampType):
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

    # GET

    def getClaimDef(self, id: ID) -> ClaimDefinition:
        if id.claimDefKey and id.claimDefKey in self._claimDefsByKey:
            return self._claimDefsByKey[id.claimDefKey]

        if id.claimDefId and id.claimDefId in self._claimDefsById:
            return self._claimDefsById[id.claimDefId]

        raise ValueError('No claim definition with ID={} and key={}'.format(id.claimDefId, id.claimDefKey))

    def getPublicKey(self, id: ID) -> PublicKey:
        return self._getValueForId(self._pks, id)

    def getPublicKeyRevocation(self, id: ID) -> RevocationPublicKey:
        return self._getValueForId(self._pkRs, id)

    def getPublicKeyAccumulator(self, id: ID) -> AccumulatorPublicKey:
        return self._getValueForId(self._accumPks, id)

    def getAccumulator(self, id: ID) -> Accumulator:
        return self._getValueForId(self._accums, id)

    def getTails(self, id: ID) -> TailsType:
        return self._getValueForId(self._tails, id)

    # SUBMIT

    def submitClaimDef(self, claimDef: ClaimDefinition):
        self._claimDefsByKey[claimDef.getKey()] = claimDef
        claimDef.id = self._claimDefId
        self._claimDefId += 1
        self._claimDefsById[claimDef.id] = claimDef

    def submitPublicKeys(self, id: ID, pk: PublicKey, pkR: RevocationPublicKey = None):
        self._cacheValueForId(self._pks, id, pk)
        if pkR:
            self._cacheValueForId(self._pkRs, id, pkR)

    def submitAccumulator(self, id: ID, accumPK: AccumulatorPublicKey, accum: Accumulator, tails: TailsType):
        self._cacheValueForId(self._accums, id, accum)
        self._cacheValueForId(self._accumPks, id, accumPK)
        self._cacheValueForId(self._tails, id, tails)

    def submitAccumUpdate(self, id: ID, accum: Accumulator, timestampMs: TimestampType):
        self._cacheValueForId(self._accums, id, accum)

    def _getValueForId(self, dict: Dict[ClaimDefinitionKey, Any], id: ID) -> Any:
        claimDefKey = self.getClaimDef(id).getKey()
        if not claimDefKey in dict:
            raise ValueError(
                'No value for claim definition with ID={} and key={}'.format(id.claimDefId, id.claimDefKey))
        return dict[claimDefKey]

    def _cacheValueForId(self, dict: Dict[ClaimDefinitionKey, Any], id: ID, value: Any):
        claimDefKey = self.getClaimDef(id).getKey()
        dict[claimDefKey] = value
