#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os
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
		json_data =  message['payload']
		if json_data["code"]:
			path = json_data["funcname"]
			path = path[:-len(path.split('/')[-1])]
			if path != '' and not os.path.exists(path):
				os.makedirs(path)
			fh = open(json_data["funcname"], 'w')
			fh.write(json_data["code"])
			fh.close()
			print('[+] ' + json_data["funcname"])
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

	var AssetCryptImpl = Java.use("%s" + ".AssetCryptImpl");

	AssetCryptImpl.readAsset.implementation = function (filename) {
		var code = this.readAsset.apply(this, arguments);
		send({funcname: filename, code: code});
		return code;
	}
});
""" % sys.argv[1])
	script.on('message', on_message)
	print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	script.load()
	if started:
		device.resume(pid)
	input()
	session.detach()	

if __name__ == '__main__':
	if len(sys.argv) != 2:
		usage = 'usage {} <process name>\n'.format(__file__)
		sys.exit(usage)
	main()
