import struct
import collections
import logging

import tls_attack.structure

# Allows us to retrieve the attributes in the order they are defined.
# http://stackoverflow.com/a/11296549
class OrderedMeta(type):
    @classmethod
    def __prepare__(metacls, name, bases): 
        return collections.OrderedDict()

    def __new__(cls, name, bases, clsdict):
        c = type.__new__(cls, name, bases, clsdict)

        keys = clsdict.keys()
        c.static_attributes = []

        for name in keys:
            # Skip internal attributes which all have the pattern __.*__
            if name[:2] == "__" and name[-2:] == "__":
                continue

            c.static_attributes.append(name)
        
        return c

class TLSStructure(metaclass = OrderedMeta):

    # Returns the references to a TLS Structure class by it's name
    def _get_tls_structure_by_name(self, type):
        # Load on demand the module required for the decoding
        if not hasattr(tls_attack.structure, type):
            __import__("tls_attack.structure." + type)

        # If the type is a class, we resolve it and use it's decoder
        return getattr(getattr(tls_attack.structure, type), type)

    # Serializes an object to raw bytes.
    def _serialize_type(self, type, type_enum, type_list, type_size, state, source, obj):
        result = b""

        if type == "int":
            # Primitive type encoder for int
            # Integer value are encoded as unsigned big endian number
            result = obj.to_bytes(type_size, byteorder='big')

        elif type == "bytes":
            # Primitive type encoder for bytes
            result = obj

        elif type == "enum":
            # Primitive type decoder to map integer value to enumeration
            result = obj.value.to_bytes(type_size, byteorder='big')

        else:
            type = self._get_tls_structure_by_name(type)

            if type_list:
                result = b""

                for item in obj:
                    result += item.encode(state, source)

            else:
                result = obj.encode(state, source)

        # Safety check to make sure we are properly encoding the value.
        # For the remaining size (undecoded value) we ignore this.
        if len(result) != type_size and type_size != TLSField.REMAINING_SIZE:
            logging.warning( \
                "Output length doesn't match the requested length. Expected : %d Given : %d " + \
                "Object : %s", type_size, len(result), str(obj) \
            )

        return result


    # Unserializes the raw bytes into the type specified.
    def _unserialize_type(self, type, type_enum, type_list, state, source, data):
        result = None
        
        if type == "int":
            # Primitive type decoder for int
            # Integer value are encoded as unsigned big endian number
            result = int.from_bytes(data, byteorder='big', signed=False)

        elif type == "bytes":
            # Primitive type decoder for bytes
            result = data

        elif type == "enum":
            # Primitive type decoder to map integer value to enumeration
            value = int.from_bytes(data, byteorder='big', signed=False)
            result = type_enum(value)

        else:
            type = self._get_tls_structure_by_name(type)

            if type_list:
                result = []
                pointer = 0

                while pointer < len(data):
                    item = type()
                    length = item.decode(data[pointer:], state, source)

                    if length == 0:
                        break
                    
                    pointer += length
                    result.append(item)

            else:
                result = type()
                result.decode(data, state, source)

        return result

    # Decodes the raw bytes provided into the current TLSStructure.
    def decode(self, raw, state, source):
        pointer = 0

        for name in self.static_attributes:
            field = getattr(type(self), name)

            # Skips field which aren't TLSField
            if type(field) is TLSField:
                field_size     = field.size.value(self)
                field_type     = field.type.value(self)
                field_type_ref = field.type_ref

                # When the state of the connection is encrypted, the encryptable field
                # should all be considered as encrypted data.
                if field.encryptable and state.encrypted[source]:
                    field_type = "TLSEncryptedData"
                    field_type_ref = None

                # If the field size is set to the remaining size
                if field_size == TLSField.REMAINING_SIZE:
                    field_size = len(raw) - pointer

                # For optional field, we check if there's still value to be decoded.
                # If there's nothing left to be decoded, it means it wasn't any value.
                if field.optional and len(raw) == pointer:
                    field_size = 0

                # Check if we have enough data, otherwise we just have the partial data
                # and we can't parse the whole structure. For this cases, we just assume
                # nothing could be decoded.
                if len(raw) < pointer + field_size:
                    return 0

                # Type references are made to implement the switch cases
                # of the TLS specification. The type reference is an enum
                # class that tells which identifier maps to which structure.
                if field_type_ref:
                    field_type = field_type_ref(field_type).name

                if field_size > 0:
                    field_data = raw[pointer : pointer + field_size]
                    field_value = self._unserialize_type(field_type, field.type_enum, field.type_list, state, source, field_data)
                else:
                    field_value = None

                setattr(self, name, field_value)
                pointer += field_size

        return pointer

    # Encodes the current TLS Structure into raw bytes
    def encode(self, state, source):
        result = b""

        for name in self.static_attributes:
            field = getattr(type(self), name)

            # Skips field which aren't TLSField
            if type(field) is TLSField:
                field_size     = field.size.value(self)
                field_type     = field.type.value(self)
                field_value    = getattr(self, name)
                field_type_ref = field.type_ref

                if type(field_value) is TLSField:
                    logging.error("Field value '%s' is of type 'TLSField'. This means no value was assigned to it !" % name) 

                # When the state of the connection is encrypted, the encryptable field
                # should all be considered as encrypted data.
                if field.encryptable and state.encrypted[source]:
                    field_type = "TLSEncryptedData"
                    field_type_ref  = None

                # For optional field, we check if there's still value to be decoded.
                # If there's nothing left to be decoded, it means it wasn't any value.
                if field.optional and field_value is None:
                    field_size = TLSField.NONE

                # Type references are made to implement the switch cases
                # of the TLS specification. The type reference is an enum
                # class that tells which identifier maps to which structure.
                if field_type_ref:
                    field_type = field_type_ref(field_type).name

                if not field_size == TLSField.NONE:
                    result += self._serialize_type(field_type, field.type_enum, field.type_list, field_size, state, source, field_value)

        return result

    # Produces a string representation of the TLSStructure element.
    # This is meant to inspect value of the structures.
    def __str__(self):
        result = type(self).__name__ + " {\n"

        for name in self.static_attributes:
            field_value = getattr(self, name)
            field_value_str = str(field_value)

            if issubclass(type(field_value), TLSStructure):
                result += " "*4 + name + " = "
                lines = field_value_str.split("\n")
                result += lines[0] + "\n"

                for line in lines[1:-1]:
                    result += " "*4 + line + "\n"

                result += " " * 4 + "}\n"

            elif isinstance(field_value, list):
                result += " "*4 + name + " = [ "

                for item in field_value:
                    lines = str(item).split("\n")
                    result += lines[0] + "\n"

                    for line in lines[1:-1]:
                        result += " "*8 + line + "\n"

                    result += " "*8	 + "}, "

                result += "\n" + " " * 4 + "]\n"
            else:
                result += " "*4 + name + " = " + field_value_str + "\n"

        result += "}"
        return result

class TLSField:

    # Constant for undecoded value that will return the remaining data
    REMAINING_SIZE = -1
    NONE = 0

    def __init__(self, size, type, type_ref = None, type_list = False, type_enum = None, encryptable = False, optional = False):
        self.size = TLSFieldValue(size) if not callable(getattr(size, "value", None)) else size
        self.type = TLSFieldValue(type) if not callable(getattr(type, "value", None)) else type
        self.type_ref = type_ref
        self.type_list = type_list
        self.type_enum = type_enum
        self.value = None
        self.encryptable = encryptable
        self.optional = optional

class TLSFieldValue:
    def __init__(self, value):
        self._value = value

    def value(self, obj):
        return self._value

class TLSFieldRef:
    def __init__(self, name):
        self.name = name

    def value(self, obj):
        ref_value = getattr(obj, self.name)
        return ref_value