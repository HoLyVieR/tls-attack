from enum import *

from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSClientKeyExchange(TLSStructure):
    key_exchange_data = TLSField(size = TLSField.REMAINING_SIZE,  type = "bytes")

