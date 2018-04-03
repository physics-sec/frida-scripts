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

def main(target_process, direccion):
	session = frida.attach(target_process)
	script = session.create_script("""
	Interceptor.replace(ptr("%s"), new NativeCallback(function (direc) {
		var pointer = Module.findExportByName(null, "printf");
		var dir = Memory.allocUtf8String("ahora yo soy la funcion f()    ");
		var print = new NativeFunction(pointer, 'void', ['pointer']);
		print(dir);
		Memory.writeInt(ptr(direc), 763364);
		return;
	}, 'void', ['pointer']));
""" % direccion)
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
	direc = int(sys.argv[2], 16)
	
	main(target_process, direc)
