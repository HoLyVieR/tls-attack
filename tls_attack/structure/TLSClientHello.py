from enum import *

from tls_attack.structure.TLSStructure import *

class TLSClientHello(TLSStructure):
    version            = TLSField(size = 2,  type = "int")
    gmt_unix_timestamp = TLSField(size = 4,  type = "int")
    random_bytes       = TLSField(size = 28, type = "bytes")
    session_id_length  = TLSField(size = 1,  type = "int")
    session_id         = TLSField(
                                size = TLSFieldRef(name = "session_id_length"), 
                                type = "bytes"
                            )
    
    cipher_suites_length = TLSField(size = 2,  type = "int")
    cipher_suites        = TLSField(
                                size = TLSFieldRef(name = "cipher_suites_length"),
                                type = "TLSCipherSuiteStruct",
                                type_list = True
                            )

    compression_methods_length = TLSField(size = 1,  type = "int")
    compression_methods        = TLSField(
                                        size = TLSFieldRef(name = "compression_methods_length"),
                                        type = "TLSCompressionStruct",
                                        type_list = True
                                    )

    extensions_length = TLSField(size = 2,  type = "int", tls_version = 0x0301)
    extensions        = TLSField(
                                size = TLSFieldRef(name = "extensions_length"),
                                type = "TLSExtension",
                                type_list = True,
                                tls_version = 0x0301
                            )