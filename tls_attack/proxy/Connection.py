import uuid

class Connection:
    def __init__(self, source_ip = None, source_port = None, dest_ip = None, dest_port = None):
        self.id = str(uuid.uuid4())

        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = dest_ip
        self.destination_port = dest_port