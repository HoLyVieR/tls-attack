from enum import *

from tls_attack.structure.TLSStructure import *

class TLSCertificate(TLSStructure):
    certificate_length = TLSField(size = 3,  type = "int")
    certificate_data   = TLSField(size = TLSFieldRef(name = "certificate_length"), type = "bytes")
