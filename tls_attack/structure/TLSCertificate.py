from enum import *

from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSCertificate(TLSStructure):
    certificate_length = TLSField(size = 3,  type = "int", default = TLSAuto())
    certificate_data   = TLSField(size = TLSFieldRef(name = "certificate_length"), type = "bytes")
