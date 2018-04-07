#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import frida
import time
import re

def on_message(message, data):
	if message['type'] == 'error':
		print('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[i] ' + message['payload'])
	else:
		print(message)

def main(target_process, pattern, old_value, new_value, usb):
	try:
		if usb:
			session = frida.get_usb_device().attach(target_process)
		else:
			session = frida.attach(target_process)
	except:
		sys.exit('The process does not exist')
	script = session.create_script("""
		var ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: true});

		for (var i = 0, len = ranges.length; i < len; i++)
		{
			Memory.scan(ranges[i].base, ranges[i].size, '%s', {
				onMatch: function(address, size){
					var numEncontrado = Memory.readInt(address);
					if(numEncontrado == %d){
						Memory.writeInt(address, %d);
					}
				},
				onError: function(reason){
					//console.log('[!] There was an error scanning memory:' + reason);
				},
				onComplete: function(){}
			});
		}
""" % (pattern, old_value, new_value))

	script.on('message', on_message)
	script.load()
	time.sleep(3)
	session.detach()

if __name__ == '__main__':
	argc = len(sys.argv)
	if argc < 4 or argc > 6:
		print('Usage: {} (-U) (little|big) <process name or PID> <old value> <new value>'.format(__file__))
		sys.exit(1)

	usb = sys.argv[1] == '-U' or sys.argv[2] == '-U'
	isLittleEndian = sys.argv[1] != 'big' and sys.argv[2] != 'big'

	if sys.argv[argc - 3].isdigit():
		target_process = int(sys.argv[argc - 3])
	else:
		target_process = sys.argv[argc - 3]

	old_value = int(sys.argv[argc - 2])

	new_value = int(sys.argv[argc - 1])

	hex_string = '{:02x}'.format(old_value)
	if len(hex_string) % 2 == 1:
	        hex_string = '0' + hex_string
	bytes = re.findall(r'.{2}', hex_string)
	hex_string = ''
	if isLittleEndian:
		for byte in bytes:
				hex_string = byte + ' ' + hex_string # little indian
		pattern = hex_string[:-1]
	else:
		for byte in bytes:
				hex_string = hex_string + ' ' + byte # big indian
		pattern = hex_string[1:]

	main(target_process, pattern, old_value, new_value, usb)
