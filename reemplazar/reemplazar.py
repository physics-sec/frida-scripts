#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import sys

def on_message(message, data):
	if message['type'] == 'error':
		print('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[i] ' + message['payload'])
	else:
		print(message)

def main(target_process):
	try:
		session = frida.attach(target_process)
	except:
		print('No existe el proceso')
		sys.exit(1)
	script = session.create_script("""
	Interceptor.replace(ptr(0x4005d6), new NativeCallback(function (pointer) {
		send("puntero:" + pointer.toString())
		Memory.writeInt(pointer, 1337);
		return;
	}, 'void', ['pointer']));
	""")
	script.on('message', on_message)
	script.load()
	input('[!] press <Enter> to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Usage: {} <process name or PID>'.format(__file__))
		sys.exit(1)

	if sys.argv[1].isdigit():
		target_process = int(sys.argv[1])
	else:
		target_process = sys.argv[1]
	
	main(target_process)
