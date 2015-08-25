from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSCertificateStatus(TLSStructure):
    data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")