from enum import *

from tls_attack.structure.TLSStructure import *

class TLSChangeCipherSpec(TLSStructure):
    type = TLSField(size = 1,  type = "int")

