from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSCertificateUrl(TLSStructure):
    data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")