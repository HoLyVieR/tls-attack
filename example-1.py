import logging
import sys

from tls_attack.proxy.HTTPSProxyServer import HTTPSProxyServer

def packet_received(connection_id, tls_object, state, source):
    print(tls_object)

#logging.basicConfig(stream=sys.stdout, level=logging.INFO)

server = HTTPSProxyServer(port = 8443)
server.on_packet_received(packet_received)
server.start()