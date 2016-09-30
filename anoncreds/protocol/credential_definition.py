from _sha256 import sha256

from config.config import cmod

from anoncreds.protocol.globals import NAME, VERSION, TYPE, TYPE_CL, ATTR_NAMES
from anoncreds.protocol.types import SerFmt
from anoncreds.protocol.utils import randomString, serialize, base58encode


class CredentialDefinition:
    def __init__(self,
                 uid,
                 attrNames,
                 name=None,
                 version=None,
                 ):
        """
        :param attrNames: List of all attribute names
        :param uid: The global unique id for this credential definition
        :param name: human-friendly name
        :param version: version (semver style)
        :return:
        """

        self.uid = uid
        self._name = name or randomString(6)
        self._version = version or "1.0"
        self.attrNames = attrNames

        if not attrNames and isinstance(attrNames, list):
            raise ValueError("List of attribute names is required to "
                             "setup credential definition")

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def version(self) -> str:
        return self._version

    @version.setter
    def version(self, version):
        self._version = version

    @classmethod
    def getEncodedAttrs(cls, attrs):
        """
        This function will encode all the attributes to 256 bit integers

        :param attrs: The attributes to pass in credentials
        :return:
        """

        return {key: cmod.Conversion.bytes2integer(sha256(value.encode()).digest())
                for key, value in attrs.items()}

    def get(self, serFmt: SerFmt=SerFmt.default):
        data = {
            NAME: self.name,
            VERSION: self.version,
            TYPE: TYPE_CL,
            ATTR_NAMES: self.attrNames
        }
        return serialize(data, serFmt)
