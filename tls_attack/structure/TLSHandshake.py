from enum import *

from tls_attack.structure.TLSStructure import *

class TLSHandshakeType(Enum):
	TLSHelloRequest       = 0
	TLSClientHello        = 1
	TLSServerHello        = 2
	TLSCertificate        = 11
	TLSServerKeyExchange  = 12
	TLSCertificateRequest = 13
	TLSServerHelloDone    = 14
	TLSCertificateVerify  = 15
	TLSClientKeyExchange  = 16
	TLSFinished           = 20

class TLSHandshake(TLSStructure):
	handshake_type = TLSField(size = 1, type = "int")
	length         = TLSField(size = 3, type = "int")
	body           = TLSField(
							size = TLSFieldRef(name = "length"), 
							type = TLSFieldRef(name = "handshake_type"),
							type_ref = TLSHandshakeType
						)
			