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

	classes.sort(function(a, b) {
		if (a < b) //sort string ascending
		 return -1;
	});

	for (i = 0; i < classes.length; i++) {
		console.log(classes[i]);
	}
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
