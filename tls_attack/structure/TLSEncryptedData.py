from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSEncryptedData(TLSStructure):
    encrypted_data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")

