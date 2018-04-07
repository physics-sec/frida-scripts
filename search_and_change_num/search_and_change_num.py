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

def main(target_process, pattern, old_value, new_value):
	try:
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
	if len(sys.argv) < 4:
		print('Usage: {} <process name or PID> (little|big) <old value> <new value>'.format(__file__))
		sys.exit(1)

	if sys.argv[1].isdigit():
		target_process = int(sys.argv[1])
	else:
		target_process = sys.argv[1]

	isLittleEndian = True
	if len(sys.argv) == 5:
		start = 2
		if sys.argv[2] == 'big':
			isLittleEndian = False
		elif sys.argv[2] != 'little':
			sys.exit('Endianness must be little or big')
	else:
		start = 1

	old_value = int(sys.argv[start + 1])

	new_value = int(sys.argv[start + 2])

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

	main(target_process, pattern, old_value, new_value)
