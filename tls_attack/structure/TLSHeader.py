from enum import *

from tls_attack.structure.TLSStructure import *

class TLSContentType(Enum):
	TLSChangeCipherSpec = 20
	TLSAlert = 21
	TLSHandshake = 22
	TLSApplicationData = 23
	TLSHeartbeat = 24

class TLSHeader(TLSStructure):
	content_type = TLSField(size = 1, type = "int")
	version      = TLSField(size = 2, type = "int")
	length       = TLSField(size = 2, type = "int")
	tls_object   = TLSField(
						size = TLSFieldRef(name = "length"), 
						type = TLSFieldRef(name = "content_type"),
						type_ref = TLSContentType
					)

