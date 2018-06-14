#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
try:
	import frida
except ImportError:
	sys.exit('install frida\nsudo pip3 install frida')

def err(msg):
	sys.stderr.write(msg + '\n')

def on_message(message, data):
	if message['type'] == 'error':
		err('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[+] ' + message['payload'])
	else:
		print(message)

def main():
	target_process = sys.argv[1]
	try:
		started = False
		session = frida.get_usb_device().attach(target_process)
	except frida.ProcessNotFoundError:
		print('Starting process {}...\n'.format(target_process))
		started = True
		device = frida.get_usb_device()
		try:
			pid = device.spawn([target_process])
		except frida.NotSupportedError:
			sys.exit('An error ocurred while attaching with the procces\n')
		session = device.attach(pid)

	script = session.create_script("""

Java.perform(function () {

	var classes = Java.enumerateLoadedClassesSync()

	for (i = 0; i < classes.length; i++) {
		var name = classes[i].split(".").slice(-1)[0];
		if (name == "HttpURLConnectionImpl") {
			var HttpURLConnectionImpl = Java.use(classes[i]);
			continue;
		}
		if (name == "InputStreamReader") {
			var InputStreamReader = Java.use(classes[i]);
			continue;
		}
		if (name == "GZIPInputStream") {
			var GZIPInputStream = Java.use(classes[i]);
			continue;
		}
	}

	HttpURLConnectionImpl.getInputStream.implementation = function () {

		var originalReturn = this.getInputStream.apply(this, arguments);

		var msg = {};
		msg.metodo = this.getRequestMethod();
		msg.url = this.getURL().toString();

		if (this.getHeaderFields) {
			var Keys = this.getHeaderFields().keySet().toArray();
			var Values = this.getHeaderFields().values().toArray();
			var headers = {};
			for (var key in Keys) {
				if (Keys[key] && Keys[key] !== null && Values[key]) {
					headers[Keys[key]] = Values[key].toString();
				}
			}
			msg.responseHeaders = headers;
		}

		if ("gzip" == this.getContentEncoding()) {
			var stream = InputStreamReader.$new(GZIPInputStream.$new(originalReturn));
		}
		else {
			var stream = InputStreamReader.$new(originalReturn);
		}

		var buffer = -1;
		var responseBody = "";
		while ((buffer = stream.read()) != -1) {
			responseBody += String.fromCharCode(buffer);
		}
		msg.response = responseBody.replace(/[^\x20-\x7E]+/g, '');
		if (msg.response.length < responseBody.length) {
			msg.trimmed = responseBody.length - msg.response.length;
		}

		console.log("\\n\\n" + JSON.stringify(msg, null, 2));

		return originalReturn;
	};
});
""")
	script.on('message', on_message)
	print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	script.load()
	if started:
		device.resume(pid)
	input()
	session.detach()	

if __name__ == '__main__':
	if len(sys.argv) != 2:
		usage = 'usage {} <process name or PID>\n'.format(__file__)
		usage += 'run \'frida-ps -U\' to list processes\n'
		sys.exit(usage)
	main()
