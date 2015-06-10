from enum import *

from tls_attack.structure.TLSStructure import *

class TLSEncryptedData(TLSStructure):
    encrypted_data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")

