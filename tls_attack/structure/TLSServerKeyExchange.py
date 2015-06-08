from enum import *

from tls_attack.structure.TLSStructure import *

class TLSServerKeyExchange(TLSStructure):
    key_exchange_data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")

