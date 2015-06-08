from enum import *

from tls_attack.structure.TLSStructure import *

class TLSClientKeyExchange(TLSStructure):
    key_exchange_data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")

