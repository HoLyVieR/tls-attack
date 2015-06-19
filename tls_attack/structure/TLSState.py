import logging

from tls_attack.structure.TLSCipherSuiteStruct import *
from tls_attack.structure.TLSCompressionStruct import *
from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSSource import *
from tls_attack.structure.TLSChangeCipherSpec import *
from tls_attack.structure.TLSHandshake import *
from tls_attack.structure.TLSServerHello import *

class TLSState:
    def __init__(self):
        self.cipher_suite = TLSCipherSuite.TLS_NULL_WITH_NULL_NULL
        self.compression  = TLSCompression.NULL
        self.encrypted = {
            TLSSource.CLIENT : False,
            TLSSource.SERVER : False 
        }

    def update(self, source, tls_object):
        if type(tls_object.body) is TLSChangeCipherSpec:
            self._handle_change_cipher_spec(source, tls_object.body)

        if type(tls_object.body) is TLSHandshake:
            self._handle_handshake(source, tls_object.body)

    def _handle_change_cipher_spec(self, source, change_cipher_spec):
        logging.info("Change Cipher Spec received. " + str(source)  + " is now encrypted.")
        self.encrypted[source] = True

    def _handle_handshake(self, source, handshake):
        if type(handshake.body) is TLSServerHello:
            logging.info("Server Hello received.")
            server_hello      = handshake.body
            self.cipher_suite = server_hello.cipher_suite
            self.compression  = server_hello.compression_methods

