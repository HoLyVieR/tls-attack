import struct

def decode(raw):
	if len(raw) < 5:
		return 0, {}

	content_type, version, length = struct.unpack(">BHH", raw[:5])
	print(content_type, version, length)

	if len(raw) < 5 + length:
		return 0, {}

	content_data = raw[5 : 5 + length]

	return length + 5, {}


def encode(structure):
	pass