;(function () { 
	window.onload=function() {
		var a = document.createElement("script"); 
		a.src = "/%s/script.js";
		document.getElementsByTagName("head")[0].appendChild(a);
	};
});