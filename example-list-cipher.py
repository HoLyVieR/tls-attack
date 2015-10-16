import logging
import sys

from tls_attack.module.ListSupportedCipher import *

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

cipher_scan = ListSupportedCipher("96.22.15.31", 443)

for version, ciphers in cipher_scan.get_ciphers_all_version().items():
	print("Version '%s'" % (version))
	
	for cipher in ciphers:
		print(cipher)
