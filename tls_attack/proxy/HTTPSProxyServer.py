import socketserver
import socket
import uuid
import pprint

from tls_attack.structure.TLSHeader import *

connection_pool = {}
connection_handler = []

class HTTPSProxyServer:

    def __init__(self, port = 8443, host = "0.0.0.0"):
        self.port = port
        self.host = host
        self.server = socketserver.TCPServer((host, port), HTTPSProxyServerHandler)
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

class HTTPSProxyServerHandler(socketserver.BaseRequestHandler):
    def send_packet(self, data):
        print("2 !")
        pass

    def _read_header(self):
        data = b""

        while not data[-4:] == b"\r\n\r\n":
            data += self.request.recv(1)


        headers = data.split(b"\r\n")[:-2]
        connection = headers[0].split(b" ")

        result = {}
        result["Method"] = connection[0]
        result["Url"] = connection[1].split(b":")[0]
        result["Port"] = int(connection[1].split(b":")[1])
        result["Protocol"] = connection[2]

        for i in range(1, len(headers)):
            line = headers[i].split(b": ", 2)
            result[line[0]] = line[1]

        return result
        

    def _get_response_header(self):
        response = b""
        response += b"HTTP/1.0 200 Connection established\r\n"
        response += b"Proxy-agent: Evil_Proxy_9000\r\n"
        response += b"\r\n"
        return response

    def _get_server_connection(self, headers):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((headers["Url"], headers["Port"]))
        return s

    def _handle_traffic(self, in_socket, out_socket, buf, connection_id):
        try:
            buf += in_socket.recv(4096)
            
            while True:
                structure = TLSHeader()
                length = structure.decode(buf)

                # When there is no more TLS Structure to decode we are done parsing the data
                if length == 0:
                    break

                print(structure)

                raw_segment = buf[:length]
                response = structure

                for handler in connection_handler:
                    response = handler(connection_id, response)

                # If the response was altered we send the modified content
                if not response	== None:
                    raw_segment	= response.encode()

                out_socket.sendall(raw_segment)
                buf = buf[length:]
        except socket.error as err:
            if err.errno == 104:
                return True, ""

        return False, buf

    def handle(self):
        print("Received connection ...")

        headers = self._read_header()
        print("Received headers ...", headers)

        if not headers["Method"] == b"CONNECT":
            self.close()
            return

        connection_id = str(uuid.uuid4())
        connection_pool[connection_id] = self

        server = self._get_server_connection(headers)
        self.request.sendall(self._get_response_header())

        server.setblocking(0)
        self.request.setblocking(0)

        buffer_reply = b""
        buffer_request = b""
        is_finished = False

        while not is_finished:
            is_finished, buffer_reply = self._handle_traffic(server, self.request, buffer_reply, connection_id)

            if not is_finished:
                is_finished, buffer_request = self._handle_traffic(self.request, server, buffer_request, connection_id)

        server.close()
        self.request.close()
        del connection_pool[connection_id]

