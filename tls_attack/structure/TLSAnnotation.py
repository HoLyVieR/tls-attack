class TLSField:

    # Constant for undecoded value that will return the remaining data
    REMAINING_SIZE = -1
    NONE = 0

    def __init__(self, size, type, type_ref = None, type_list = False, type_enum = None, encryptable = False, optional = False, default = None):
        self.size = TLSFieldValue(size) if not callable(getattr(size, "value", None)) else size
        self.type = TLSFieldValue(type) if not callable(getattr(type, "value", None)) else type
        self.type_ref = type_ref
        self.type_list = type_list
        self.type_enum = type_enum
        self.value = None
        self.encryptable = encryptable
        self.optional = optional
        self.default_value = default

class TLSFieldValue:
    def __init__(self, value):
        self._value = value

    def value(self, obj):
        return self._value

class TLSFieldRef:
    def __init__(self, name):
        self.name = name

    def value(self, obj):
        ref_value = getattr(obj, self.name)
        return ref_value

class TLSAuto:
    pass