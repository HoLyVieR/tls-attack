import struct
import collections

import tls_attack.structure

# http://stackoverflow.com/a/11296549
class OrderedMeta(type):
    @classmethod
    def __prepare__(metacls, name, bases): 
        return collections.OrderedDict()

    def __new__(cls, name, bases, clsdict):
        c = type.__new__(cls, name, bases, clsdict)
        c._orderedKeys = clsdict.keys()
        return c

class TLSStructure(metaclass=OrderedMeta):
	def __init__(self):
		pass

	def _parseType(self, type, type_ref, data):
		if type_ref:
			type = type_ref(type).name

		result = None

		
		if type == "int":
			# Primitive type decoder for int
			result = int.from_bytes(data, byteorder='big', signed=False)
		elif type == "bytes":
			# Primitive type decoder for bytes
			result = data
		else:
			# Load on demand the module required for the decoding
			if not hasattr(tls_attack.structure, type):
				__import__("tls_attack.structure." + type)

			# If the type is a class, we resolve it and use it's decoder
			type = getattr(getattr(tls_attack.structure, type), type)
			result = type()
			result.decode(data)

		return result

	def __str__(self):
		result = "{\n"
		attributes = self._orderedKeys

		for name in attributes:
			# Skip internal attributes which all have the pattern __.*__
			if name[:2] == "__":
				continue

			field_value = getattr(self, name).value
			field_value_str = str(field_value)

			if issubclass(type(field_value), TLSStructure):
				result += " "*4 + name + " = {\n"
				lines = field_value_str.split("\n")

				for line in lines[1:-1]:
					result += " "*4 + line + "\n"

				result += " " * 4 + "}\n"

			else:
				result += " "*4 + name + " = " + field_value_str + "\n"

		result += "}"
		return result

	def decode(self, raw):
		attributes = self._orderedKeys
		pointer = 0

		for name in attributes:
			# Skip internal attributes which all have the pattern __.*__
			if name[:2] == "__":
				continue

			field = getattr(self, name)

			if type(field) is TLSField:
				field_size = field.size.value(self)
				field_type = field.type.value(self)
				field_type_ref = field.type_ref

				# Check if we have enough data, otherwise we just have the partial data
				# and we can't parse the whole structure
				if len(raw) < pointer + field_size:
					return 0

				field_data = raw[pointer : pointer + field_size]
				field_value = self._parseType(field_type, field_type_ref, field_data)

				field.value = field_value
				pointer += field_size

		return pointer

	def encode(self):
		pass

class TLSField:
	def __init__(self, size, type, type_ref = None):
		self.size = TLSFieldValue(size) if not callable(getattr(size, "value", None)) else size
		self.type = TLSFieldValue(type) if not callable(getattr(type, "value", None)) else type
		self.type_ref = type_ref
		self.value = None

class TLSFieldValue:
	def __init__(self, value):
		self._value = value

	def value(self, obj):
		return self._value

class TLSFieldRef:
	def __init__(self, name):
		self.name = name

	def value(self, obj):
		ref_value = getattr(obj, self.name).value
		return ref_value