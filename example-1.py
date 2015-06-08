import logging
import sys

from tls_attack.proxy.HTTPSProxyServer import HTTPSProxyServer

def packet_received():
    pass

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

server = HTTPSProxyServer(port = 8443)
server.start()