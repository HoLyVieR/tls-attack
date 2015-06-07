from enum import *

from tls_attack.structure.TLSStructure import *

class TLSClientHello(TLSStructure):
    client_version     = TLSField(size = 2,  type = "int")
    random_timestamp   = TLSField(size = 4,  type = "int")
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

    compresssion_methods_length = TLSField(size = 1,  type = "int")
    compresssion_methods        = TLSField(
                                        size = TLSFieldRef(name = "compresssion_methods_length"),
                                        type = "TLSCompression",
                                        #type_list = True
                                    )

    extensions_length = TLSField(size = 2,  type = "int")
    extensions        = TLSField(
                                size = TLSFieldRef(name = "extensions_length"),
                                type = "TLSExtension",
                                #type_list = True
                            )