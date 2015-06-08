from enum import *

from tls_attack.structure.TLSStructure import *

class TLSExtensionType(Enum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    CLIENT_CERTIFICATE_URL = 2
    TRUSTED_CA_KEYS = 3
    TRUNCATED_HMAC = 4
    STATUS_REQUEST = 5
    USER_MAPPING = 6
    CLIENT_AUTHZ = 7
    SERVER_AUTHZ = 8
    CERT_TYPE = 9
    ELLIPTIC_CURVES = 10
    EC_POINT_FORMATS = 11
    SRP = 12
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    STATUS_REQUEST_V2 = 17
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MASTER_SECRET = 23
    SESSION_TICKET_TLS = 35
    NEXT_PROTOCOL_NEGOTIATION = 13172
    RENEGOTIATION_INFO = 65281

class TLSExtension(TLSStructure):
    extension_type        = TLSField(size = 2, type = "enum", type_enum = TLSExtensionType)
    extension_data_length = TLSField(size = 2, type = "int")
    extension_data        = TLSField(
                                size = TLSFieldRef(name = "extension_data_length"), 
                                type = "bytes"
                            )
