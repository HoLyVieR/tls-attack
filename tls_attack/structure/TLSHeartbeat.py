from enum import *

from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSHeartbeatMessageType(Enum):
    HEARTBEAT_REQUEST = 1
    HEARTBEAT_RESPONSE = 2

class TLSHeartbeat(TLSStructure):
    heartbeat_type = TLSField(size = 1, type = "enum", type_enum = TLSHeartbeatMessageType)
    length         = TLSField(size = 2, type = "int")
    payload        = TLSField(size = TLSField.REMAINING_SIZE, type = "bytes")