#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import frida
import time

def on_message(message, data):
	if message['type'] == 'error':
		print('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[i] ' + message['payload'])
	else:
		print(message)

def main(target_process, addr, size):
	session = frida.attach(target_process)
	script = session.create_script("""
		var buf = Memory.readByteArray(ptr('0x%x'), %d);
		 console.log(hexdump(buf, {
	 		offset: 0, 
		 		length: %d, 
		 		header: true,
		 		ansi: false
		 	}));
""" % (addr, size, size))

	script.on('message', on_message)
	script.load()
	time.sleep(2)
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print('Usage: {} <process name or PID> <addr> <size>'.format(__file__))
		sys.exit(1)

	if sys.argv[1].isdigit():
		target_process = int(sys.argv[1])
	else:
		target_process = sys.argv[1]

	addr, size = int(sys.argv[2], 16), int(sys.argv[3])
	main(target_process, addr, size)
