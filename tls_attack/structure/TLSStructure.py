import struct
import collections
import logging
import types

from tls_attack.structure.TLSAnnotation import TLSAuto, TLSField, TLSFieldRef

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
    def __init__(self, **kwargs):
        self._state  = self._get_tls_structure_by_name("TLSState")()
        self._source = self._get_tls_structure_by_name("TLSSource").CLIENT

        # Setting the default values for every field
        for name in self.static_attributes:
            field = getattr(type(self), name)
            setattr(self, name, field.default_value)

        # Setting the defined value by the arguments
        for key in kwargs:
            value = kwargs[key]

            if not key in self.static_attributes:
                class_name = type(self).__name__
                prop_list = ", ".join(self.static_attributes)
                raise Exception("'%s' is not a valid property name for the structure '%s'. Must be one of : %s." % (key, class_name, prop_list))

            setattr(self, key, value)

    # Returns the references to a TLS Structure class by it's name
    def _get_tls_structure_by_name(self, type_name):
        # Load on demand the module required for the decoding
        if not hasattr(tls_attack.structure, type_name):
            __import__("tls_attack.structure." + type_name)

        value = getattr(tls_attack.structure, type_name)

        if type(value) is types.ModuleType:
            value = getattr(value, type_name)

        return value

    # Returns the computed value of a field for which the value was
    # set to "auto".
    def _evaluate_auto_field(self, field_name):
        for name in self.static_attributes:
            field = getattr(type(self), name)

            # Resolves field size reference
            if type(field.size) is TLSFieldRef:
                if field.size.name == field_name:
                    value = getattr(self, name)

                    # If the length refers to an object, we need to encode it
                    # to know it's actual length
                    if issubclass(type(value), TLSStructure):
                        encoded_value = value.encode(self._state, self._source)
                        value = encoded_value

                    # If the length refers to a list, the value as to be the length
                    # of all the components
                    if field.type_list:
                        total_length = 0

                        for element in value:
                            if issubclass(type(element), TLSStructure):
                                encoded_value = element.encode(self._state, self._source)
                                total_length += len(encoded_value)
                            else:
                                total_length += len(element)

                        return total_length

                    return len(value)

            if type(field.type) is TLSFieldRef:
                if field.type.name == field_name:
                    class_name = type(getattr(self, name)).__name__
                    value = getattr(field.type_ref, class_name).value
                    return value


        return None

    # Serializes an object to raw bytes.
    def _serialize_type(self, type_name, type_enum, type_list, type_size, state, source, obj):
        result = b""

        if type_name == "int":
            # Primitive type encoder for int
            # Integer value are encoded as unsigned big endian number
            result = obj.to_bytes(type_size, byteorder='big')

        elif type_name == "bytes":
            # Primitive type encoder for bytes
            result = obj

        elif type_name == "enum":
            # Primitive type decoder to map integer value to enumeration
            result = obj.value.to_bytes(type_size, byteorder='big')

        else:
            type_name = self._get_tls_structure_by_name(type_name)

            if type_list:
                result = b""

                for item in obj:
                    result += item.encode(state, source)

            else:
                result = obj.encode(state, source)

        # Safety check to make sure we are properly encoding the value.
        # For the remaining size (undecoded value) we ignore this.
        if not type(type_size) is TLSAuto and len(result) != type_size and type_size != TLSField.REMAINING_SIZE:
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
    def decode(self, raw, state = None, source = None):
        pointer = 0

        state  = self._state  if state  is None else state
        source = self._source if source is None else source

        self._state  = state
        self._source = source

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
    def encode(self, state = None, source = None):
        result = b""

        state  = self._state  if state  is None else state
        source = self._source if source is None else source

        self._state = state
        self._source = source

        for name in self.static_attributes:
            field = getattr(type(self), name)

            # Skips field which aren't TLSField
            if type(field) is TLSField:
                field_size     = field.size.value(self)
                field_type     = field.type.value(self)
                field_value    = getattr(self, name)
                field_type_ref = field.type_ref

                if type(field_value) is TLSAuto:
                    field_value = self._evaluate_auto_field(name)

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
                    if type(field_type) is TLSAuto:
                        field_type = type(field_value).__name__
                    else:
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
                if type(field_value) is TLSAuto:
                    field_value_str = str(self._evaluate_auto_field(name))

                result += " "*4 + name + " = " + field_value_str + "\n"

        result += "}"
        return result

