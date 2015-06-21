import socketserver
import socket
import urllib.parse
import urllib
import logging
import threading

from tls_attack.proxy.Connection import *

url_request_handler = []
url_response_handler = []

class HTTPProxyServer:
    def __init__(self, port = 8443, host = "0.0.0.0"):
        self.port = port
        self.host = host
        self.server = ThreadedTCPServer((host, port), HTTPProxyServerHandler)
        self.is_started = False

    def start(self):
        def server_thread():
            self.server.serve_forever()

        if not self.is_started:
            self.is_started = True
            
            t = threading.Thread(target=server_thread)
            t.start()
            
            logging.info("HTTP Server started.")

    def on_url_request(self, callback):
        url_request_handler.append(callback)

    def on_url_response(self, callback):
        url_response_handler.append(callback)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class HTTPRequest:
    def __init__(self, host, url, headers, body, raw):
        self.host = host
        self.raw = raw
        self.url = url
        self.headers = headers
        self.body = body

class HTTPResponse:
    def __init__(self, response_code, response_name, headers, body, raw):
        self.raw = raw
        self.headers = headers
        self.response_code = response_code
        self.response_name = response_name
        self.body = body

    @staticmethod
    def create_response_from_content(content, content_type):
        headers = {
            b"Content-Type" : content_type,
            b"Content-Length" : bytes(str(len(content)), "ascii"),
            b"Server" : b"Evil_Proxy_9000",
            b"Connection" : b"close"
        }
        raw = \
            b"HTTP/1.1 200 OK\r\n" + \
            HTTPResponse._flatten_headers(headers) + \
            b"\r\n"*2 + content

        return HTTPResponse(200, "OK", headers, content, raw)

    @staticmethod
    def _flatten_headers(headers):
        print(headers)
        return b"\r\n".join(map(lambda b: b + b": " + headers[b], headers))

    def append_body(self, content):
        return self.replace_body(self.body + content)

    def replace_body(self, content):
        new_body = content
        new_headers = dict(self.headers)
        new_headers[b"Content-Length"] = bytes(str(len(new_body)), "ascii")
        new_raw = \
                b"HTTP/1.1 " + self.response_code + b" " + self.response_name + b"\r\n" + \
                HTTPResponse._flatten_headers(new_headers) + \
                b"\r\n"*2 + new_body

        return HTTPResponse(self.response_code, self.response_name, new_headers, new_body, new_raw)


class HTTPConnection(Connection):
    pass

class HTTPProxyServerHandler(socketserver.BaseRequestHandler):
    def _read(self, buffer, handler, is_request):
        buffer += handler.recv(4096)

        if not b"\r\n"*2 in buffer:
            return buffer, None

        logging.info("Buffer : %s" % buffer[0:500])

        header, body = buffer.split(b"\r\n"*2, 1)
        headers = header.split(b"\r\n")
        headers_map = {}
        url = None

        if is_request:
            method, url, protocol = headers[0].split(b" ")
        else:
            protocol, response_code, response_name = headers[0].split(b" ", 2)

        # We check the Content-Length header to make sure that we have received
        # the whole data for the request
        for line in headers[1:]:
            name, value = line.split(b": ", 1)
            headers_map[name] = value

            if name == b"Content-Length":
                if len(body) < int(value):
                    return buffer, None

        if not url is None:
            parsed_url = urllib.parse.urlparse(url)
            host = parsed_url.netloc

            if not parsed_url.port is None:
                host += b":" + str(parsed_url.port)
            else:
                host += b":80"
            
            # We remove the host and scheme part from the request that will be sent 
            # to the actual server
            parsed_url = urllib.parse.ParseResult(b"", b"", parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)
            url = urllib.parse.urlunparse(parsed_url)
            
            # And reconstruct the request with the modification to the URL
            headers[0] = b" ".join([method, url, protocol])
            header = b"\r\n".join(headers)

        content = header + b"\r\n" * 2 + body

        if is_request:
            return b"", HTTPRequest(host, url, headers_map, body, content)
        else:
            return b"", HTTPResponse(response_code, response_name, headers_map, body, content)

    def _process_request(self, request, connection):
        logging.info("Received request for the host '%s' with the url '%s'." % (request.host, request.url))

        # URL request handler are triggered before the request, since
        # they can return a custom response to the request
        for callback in url_request_handler:
            result = callback(connection, request)

            if result is None:
                continue

            # You can send a custom response to a request by
            # returning a HTTPResponse directly.
            if type(result) is HTTPResponse:
                self.request.sendall(result.raw)
                return

        # If there was no custom response, we do the actual request to 
        # the server.
        addr, port = request.host.split(b":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((addr, int(port)))
        s.send(request.raw)

        # Grabs the response once it's fully received.
        buffer_server = b""
        
        while True:
            buffer_server, response = self._read(buffer_server, s, False)

            if not response is None:
                break

        logging.info("Received response for the host '%s' with the url '%s'. Code : %s" % (request.host, request.url, response.response_code))

        # Triggering the url response event
        for callback in url_response_handler:
            result = callback(connection, request, response)

            if result is None:
                continue

            # If a modification was done to the response, 
            # we still continue with the handler since they may
            # do other modification to the modified result.
            if type(result) is HTTPResponse:
                response = result

        self.request.sendall(response.raw)

    def handle(self):
        logging.info("Received connection.")

        peer_info = self.request.getpeername()
        connection = HTTPConnection(source_ip = peer_info[0], source_port = peer_info[1])
        buffer_client = b""

        while True:
            buffer_client, request = self._read(buffer_client, self.request, True)

            if not request is None:
                # Updating the connection with the destination information
                host, port = request.host.split(b":")
                connection.destination_ip   = socket.gethostbyname(host)
                connection.destination_port = int(port)

                self._process_request(request, connection)
                break

        logging.info("Request completed.")
