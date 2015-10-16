import logging
import socket
import time
import os

from tls_attack.structure import *

class ListSupportedCipher:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port

	def get_ciphers_all_version(self):
		ciphers = {}

		for version in TLSVersion:
			ciphers[str(version)] = self.get_ciphers(version)

		return ciphers

	def get_ciphers(self, tls_version = TLSVersion.TLS10):
		ciphers = []

		for cipher in TLSCipherSuite:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((self.ip, self.port))

			hello = self._get_client_hello(tls_version, cipher)
			s.send(hello.encode())

			response = self._get_next_structure(s)
			logging.info("[ListSupportedCipher] Asked for cipher '%s' got response '%s'." % (str(cipher), str(response)))

			if type(response.body) is TLSAlert:
				if response.body.description == TLSAlertDescription.HANDSHAKE_FAILURE:
					# Cipher is not supported
					continue
				else:
					logging.warn("[ListSupportedCipher] Unexpected error when checking for cipher '%s' got '%s'." % (str(cipher), str(response.body.description)))
			else:
				if type(response.body) is TLSHandshake and type(response.body.body) is TLSServerHello:
					ciphers.append(cipher)
				else:
					logging.warn("[ListSupportedCipher] Unexpected response when checking for cipher '%s' got '%s'." % (str(cipher), str(response.body.description)))

		return ciphers

	def _get_next_structure(self, connection):
		buf = b""

		while True:
			buf += connection.recv(1)
			header = TLSHeader()

			if not header.decode(buf) == 0:
				break

		return header

	def _get_client_hello(self, tls_version, cipher_suite, compression_method = TLSCompression.NULL):
		return TLSHeader (
            version = tls_version,
            body = TLSHandshake (
                body = TLSClientHello (
                    version = tls_version,
                    gmt_unix_timestamp = int(time.time()),
                    random_bytes = os.urandom(28),
                    cipher_suites = [
                        TLSCipherSuiteStruct ( cipher_suite =  cipher_suite )
                    ],
                    compression_methods = [ TLSCompressionStruct (
                        compression_method = compression_method
                    ) ],
                    extensions = [ 
                    ]
                )
            )
        )