#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
try:
	import frida
except ImportError:
	sys.exit('install frida\nsudo python3 -m pip install frida')

def err(msg):
	sys.stderr.write(msg + '\n')

def on_message(message, data):
	if message['type'] == 'error':
		err('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[+] ' + message['payload'])
	else:
		print(message)

def kill_process(target_process):
	cmd = 'adb shell pm clear {} 1> /dev/null'.format(target_process)
	os.system(cmd)

def main():
	target_process = sys.argv[1]
	#kill_process(target_process)
	device = frida.get_usb_device()
	try:
		started = False
		session = device.attach(target_process)
	except frida.ProcessNotFoundError:
		print('Starting process {}...\n'.format(target_process))
		started = True
		try:
			pid = device.spawn([target_process])
		except frida.NotSupportedError:
			sys.exit('An error ocurred while attaching with the procces\n')
		session = device.attach(pid)

	script = session.create_script("""
Java.perform(function () {

	var Log = Java.use("android.util.Log");

	Log.e.overload('java.lang.String', 'java.lang.String').implementation = function (tag, entry) {
		console.log('Log.e( ' + tag + ', ' + entry + ' )');
		console.log('');
		return this.e.apply(this, arguments);
	}

	Log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, entry) {
		console.log('Log.w( ' + tag + ', ' + entry + ' )');
		console.log('');
		return this.w.apply(this, arguments);
	}

	Log.i.overload('java.lang.String', 'java.lang.String').implementation = function (tag, entry) {
		console.log('Log.i( ' + tag + ', ' + entry + ' )');
		console.log('');
		return this.i.apply(this, arguments);
	}

	Log.d.overload('java.lang.String', 'java.lang.String').implementation = function (tag, entry) {
		console.log('Log.d( ' + tag + ', ' + entry + ' )');
		console.log('');
		return this.d.apply(this, arguments);
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
		usage = 'usage {} <process name or PID>\n\n'.format(__file__)
		sys.exit(usage)
	main()
