import socketserver
import socket
import uuid
import pprint
import logging
import traceback
import threading

from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSState import *

connection_pool = {}
connection_handler = []

class HTTPSProxyServer:

    def __init__(self, port = 8443, host = "0.0.0.0"):
        self.port = port
        self.host = host
        self.server = ThreadedTCPServer((host, port), HTTPSProxyServerHandler)
        self.is_started = False

    def start(self):
        def server_thread():
            self.server.serve_forever()

        if not self.is_started:
            self.is_started = True
            
            t = threading.Thread(target=server_thread)
            t.start()
            
            logging.info("HTTPS Server started.")

    def on_packet_received(self, callback):
        connection_handler.append(callback)

    def send_packet(self, connection_id, destination, data):
        if not self.is_started:
            raise Exception("Proxy not started !")

        if not connection_id in connection_pool:
            raise Exception("Invalid connection ID. The connection was probably closed.")

        return connection_pool[connection_id].send_packet(destination, data)

    def get_input_source(self):
        return self

    def get_output_source(self):
        return self

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class HTTPSProxyServerHandler(socketserver.BaseRequestHandler):
    def send_packet(self, destination, data):
        print("Sending %s to %s" % (repr(data), str(destination)))

        if destination == TLSSource.CLIENT:
            self.request.sendall(data)
        else:
            self.server.sendall(data)

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
        response  = b""
        response += b"HTTP/1.0 200 Connection established\r\n"
        response += b"Proxy-agent: Evil_Proxy_9000\r\n"
        response += b"\r\n"
        return response

    def _get_server_connection(self, headers):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((headers["Url"], headers["Port"]))
        return s

    def _handle_traffic(self, in_socket, out_socket, buf, connection_id, state, source):
        try:
            try:
                buf += in_socket.recv(4096)
            except:
                pass

            while True:
                # If nothing was received, we can exit right away
                if len(buf) == 0:
                    break

                logging.info("[%s] %s."% (connection_id, repr(buf)))

                structure = TLSHeader()
                length = structure.decode(buf, state, source)

                # When there is no more TLS Structure to decode we are done parsing the data
                if length == 0:
                    break

                logging.info("[%s] %s."% (connection_id, structure))
                state.update(source, structure)

                raw_segment = buf[:length]
                response = structure

                for handler in connection_handler:
                    handler_response = None

                    try:
                        handler_response = handler(connection_id, response, state, source)
                    except Exception as e:
                        logging.error(traceback.format_exc())

                    # If nothing is returned or the handler failed, we don't change the structure.
                    if not handler_response is None:
                        
                        # Sanity check to make sure we are still handling TLStructure.
                        if issubclass(type(handler_response), TLSStructure):
                            response = handler_response
                        else:
                            logging.error("[%s] Value returned from handler must be either None or a TLSStructure. Received '%s' of type '%s'." % (connection_id, handler_response, str(type(handler_response))))

                # If the response was altered we send the modified content
                if not response	== None:
                    raw_segment	= response.encode(state, source)

                out_socket.sendall(raw_segment)
                buf = buf[length:]
        except socket.error as err:
            if err.errno == 104:
                return True, ""

        return False, buf

    def handle(self):
        logging.info("Received connection ...")

        headers = self._read_header()
        logging.info("Received headers ...", headers)

        if not headers["Method"] == b"CONNECT":
            self.close()
            return

        connection_id = str(uuid.uuid4())
        connection_pool[connection_id] = self

        self.server = self._get_server_connection(headers)
        self.request.sendall(self._get_response_header())
        logging.info("[%s] Connection established." % connection_id)

        self.server.setblocking(0)
        self.server.settimeout(0.0)
        self.request.setblocking(0)
        self.request.settimeout(0.0)

        buffer_reply = b""
        buffer_request = b""
        is_finished = False

        # Initializating the state of the connection
        self.state = TLSState()

        while not is_finished:
            is_finished, buffer_reply = self._handle_traffic(self.server, self.request, buffer_reply, connection_id, self.state, TLSSource.SERVER)

            if not is_finished:
                is_finished, buffer_request = self._handle_traffic(self.request, self.server, buffer_request, connection_id, self.state, TLSSource.CLIENT)

        logging.info("[%s] Connection terminated." % connection_id)
        self.server.close()
        self.request.close()
        del connection_pool[connection_id]

