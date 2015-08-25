from enum import *

from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSCompression(Enum):
    DEFLATE = 1
    NULL = 0

class TLSCompressionStruct(TLSStructure):
    compression_method = TLSField(size = 1, type = "enum", type_enum = TLSCompression)