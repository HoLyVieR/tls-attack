from enum import *

from tls_attack.structure.TLSStructure import TLSStructure
from tls_attack.structure.TLSAnnotation import *

class TLSNewSessionTicket(TLSStructure):
    ticket_lifetime_hint = TLSField(size = 4, type = "int")
    ticket_length        = TLSField(size = 2, type = "int", default = TLSAuto())
    ticket               = TLSField(
                                size = TLSFieldRef(name = "ticket_length"), 
                                type = "bytes"
                            )
