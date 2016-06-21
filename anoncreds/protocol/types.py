from hashlib import sha256

from charm.toolbox.conversion import Conversion


class AttribType:
    def __init__(self, name: str, encode: bool):
        self.name = name
        self.encode = encode


class Attribs:
    def __init__(self, credType, **vals):
        self.credType = credType
        self.vals = vals

    def encoded(self):
        """
        This function will encode all the attributes to 256 bit integers
        :param attrs: The attributes to pass in credentials
        :return:
        """
        named = {}
        for i in range(len(self.credType.name_a)):
            name = self.credType.name_a[i]
            attr_types = self.credType.attr_types_a[i]
            encoded = {}
            for at in attr_types:
                if at.encode:
                    encoded[at.name] = Conversion.bytes2integer(
                        sha256(str(self.vals[at.name]).encode()).digest())
                else:
                    encoded[at.name] = self.vals[at.name]
            named[name] = encoded
        return named

    def __add__(self, other):
        vals = self.vals.copy()
        vals.update(other.vals)
        return Attribs(self.credType + other.credType, **vals)


class AttribsDef:
    def __init__(self, name, attr_types):
        if isinstance(name, str):
            self.name_a = [name]
            self.attr_types_a = [attr_types]
        else:
            self.name_a = name
            self.attr_types_a = attr_types

    def __getattr__(self, item):
        for attr_types in self.attr_types_a:
            for at in attr_types:
                if item == at.name:
                    return at
            raise AttributeError

    def attribs(self, **vals):
        return Attribs(self, **vals)

    def __add__(self, other):
        return AttribsDef(self.name_a + other.name_a,
                          self.attr_types_a + other.attr_types_a)


GVT = AttribsDef('gvt',
                 [AttribType('name', encode=True),
                  AttribType('age', encode=False),
                  AttribType('sex', encode=True)])

IBM = AttribsDef('ibm',
                 [AttribType('status', encode=True)])

NASEMP = GVT + IBM
