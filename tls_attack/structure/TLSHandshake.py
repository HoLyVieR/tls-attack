from enum import *

from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSHandshakeType(Enum):
    TLSHelloRequest       = 0
    TLSClientHello        = 1
    TLSServerHello        = 2
    TLSNewSessionTicket   = 4
    TLSCertificateStruct  = 11
    TLSServerKeyExchange  = 12
    TLSCertificateRequest = 13
    TLSServerHelloDone    = 14
    TLSCertificateVerify  = 15
    TLSClientKeyExchange  = 16
    TLSFinished           = 20
    TLSCertificateUrl     = 21
    TLSCertificateStatus  = 22

class TLSHandshake(TLSStructure):
    handshake_type = TLSField(size = 1, type = "int", default = TLSAuto())
    length         = TLSField(size = 3, type = "int", default = TLSAuto())
    body           = TLSField(
                            size = TLSFieldRef(name = "length"), 
                            type = TLSFieldRef(name = "handshake_type"),
                            type_ref = TLSHandshakeType
                        )
            