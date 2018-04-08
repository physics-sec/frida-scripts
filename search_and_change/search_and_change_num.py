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
		sys.exit('An error ocurred while attaching with the procces')
	script = session.create_script("""
		var ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: true});

		for (var i = 0, len = ranges.length; i < len; i++)
		{
			Memory.scan(ranges[i].base, ranges[i].size, '%s', {
				onMatch: function(address, size){
					var numEncontrado = Memory.readInt(address);
					if(numEncontrado == %d){
						console.log('Encontrado:' + address);
						Memory.writeInt(address, %d);
					}
					else{
						console.log('No encontado:' + address);
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

def get_pattern(number, isLittleEndian, registerSize):
	hex_string = '{:02x}'.format(number)
	if len(hex_string) % 2 == 1:
		hex_string = '0' + hex_string
	bytes = re.findall(r'.{2}', hex_string)
	hex_string = ''
	if isLittleEndian:
		for byte in bytes:
			hex_string = byte + ' ' + hex_string # little indian
		pattern = hex_string[:-1]
		cantBytes = len(pattern.split(' '))
		if cantBytes < registerSize:
			for x in range(registerSize - cantBytes):
				pattern = pattern + ' 00'
	else:
		for byte in bytes:
			hex_string = hex_string + ' ' + byte # big indian
		pattern = hex_string[1:]
		cantBytes = len(pattern.split(' '))
		if cantBytes < registerSize:
			for x in range(registerSize - cantBytes):
				pattern = '00 ' + pattern
	return pattern

if __name__ == '__main__':
	argc = len(sys.argv)
	if argc < 4 or argc > 6:
		usage = 'Usage: {} (-U) (little|big) <process name or PID> <old value> <new value>'.format(__file__)
		usage += '\nUse the little (default) or big parameter to specify the endiannes.'
		usage += '\nThe -U option is for mobile instrumentation.'
		usage += '\nOld value is the number to be replace with new value'
		sys.exit(usage)

	usb = sys.argv[1] == '-U' or sys.argv[2] == '-U'
	isLittleEndian = sys.argv[1] != 'big' and sys.argv[2] != 'big'
	registerSize = 8

	if sys.argv[argc - 3].isdigit():
		target_process = int(sys.argv[argc - 3])
	else:
		target_process = sys.argv[argc - 3]

	old_value = int(sys.argv[argc - 2])

	new_value = int(sys.argv[argc - 1])

	pattern = get_pattern(old_value, isLittleEndian, registerSize)

	print(pattern)
	main(target_process, pattern, old_value, new_value, usb)
