from tls_attack.proxy.HTTPSProxyServer import HTTPSProxyServer

def packet_received():
	pass

server = HTTPSProxyServer(port = 8443)
server.start()
server.on_packet_received(packet_received)