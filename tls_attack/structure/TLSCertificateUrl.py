from tls_attack.structure.TLSStructure import *

class TLSCertificateUrl(TLSStructure):
    data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")