import SocketServer
import socket
import uuid
from tls_attack.structure.TLSStructure import *

connection_pool = {}
connection_handler = []

class HTTPSProxyServer:

	def __init__(self, port = 8443, host = "0.0.0.0"):
		self.port = port
		self.host = host
		self.server = SocketServer.TCPServer((host, port), HTTPSProxyServerHandler)
		self.is_started = False

	def start(self):
		if not self.is_started:
			self.server.serve_forever()
			self.is_started = True

	def on_packet_received(self, callback):
		connection_handler.append(callback)

	def send_packet(self, connection, destination, data):
		if not self.is_started:
			return Exception("Proxy not started !")

		if not connection.id in connection_pool:
			return Exception("Invalid connection ID. The connection was probably closed.")

		return connection_pool[connection.id].send_packet(destination, data)

	def get_input_source(self):
		return self

	def get_output_source(self):
		return self

class HTTPSProxyServerHandler(SocketServer.BaseRequestHandler):
	def send_packet(self, data):
		print("2 !")
		pass

	def read_header(self):
		data = ""

		while not data[-4:] == "\r\n\r\n":
			data += self.request.recv(1)

		headers = data.split("\r\n")[:-2]
		connection = headers[0].split(" ")

		result = {}
		result["Method"] = connection[0]
		result["Url"] = connection[1].split(":")[0]
		result["Port"] = int(connection[1].split(":")[1])
		result["Protocol"] = connection[2]

		for i in range(1, len(headers)):
			line = headers[i].split(": ", 2)
			result[line[0]] = line[1]

		return result
		

	def get_response_header(self):
		response = ""
		response += "HTTP/1.0 200 Connection established\r\n"
		response += "Proxy-agent: Evil_Proxy_9000\r\n"
		response += "\r\n"
		return response

	def get_server_connection(self, headers):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((headers["Url"], headers["Port"]))
		return s

	def handle_traffic(self, in_socket, out_socket, buf):
		try:
			buf += in_socket.recv(4096)
			
			while True:
				length, structure = decode(buf)

				# When there is no more TLS Structure to decode we are done parsing the data
				if length == 0:
					break

				raw_segment = buf[:length]
				response = None

				for handler in connection_handler:
					response = handler()

				# If the response was altered we send the modified content
				if not response	== None:
					raw_segment	= encode(response)

				out_socket.sendall(raw_segment)
				buf = buf[length:]
		except socket.error as err:
			if err.errno == 104:
				return True, ""

		return False, buf

	def handle(self):
		headers = self.read_header()
		
		if not headers["Method"] == "CONNECT":
			self.close()
			return

		connection_id = str(uuid.uuid4())
		connection_pool[connection_id] = self

		server = self.get_server_connection(headers)
		self.request.sendall(self.get_response_header())

		server.setblocking(0)
		self.request.setblocking(0)

		buffer_reply = ""
		buffer_request = ""
		is_finished = False

		while not is_finished:
			is_finished, buffer_reply = self.handle_traffic(server, self.request, buffer_reply)

			if not is_finished:
				is_finished, buffer_request = self.handle_traffic(self.request, server, buffer_request)

		server.close()
		self.request.close()
		del connection_pool[connection_id]

