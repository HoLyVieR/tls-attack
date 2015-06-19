from tls_attack.structure.TLSStructure import *

class TLSCertificateStatus(TLSStructure):
    data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")