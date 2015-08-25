from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSChangeCipherSpec(TLSStructure):
    type = TLSField(size = 1,  type = "int")

