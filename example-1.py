from tls_attack.proxy.HTTPSProxyServer import HTTPSProxyServer

def packet_received():
	pass

server = HTTPSProxyServer(port = 8444)
server.start()