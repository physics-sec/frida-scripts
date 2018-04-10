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

def main(target_process, usb, pattern, old_value, new_value, signed, bits):
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

					var old_value = %d;
					var new_value = %d;
					var signed = '%s' == 's';
					var bits = %d; //64, 32 or 8

					if (signed){
						if (bits == 64){
							if (Memory.readS64(address) == old_value){
								Memory.writeS64(address, new_value);
							}
						}
						else if (bits == 32){
							if (Memory.readS32(address) == old_value){
								Memory.writeS32(address, new_value);
							}
						}
						else{
							if (Memory.readS8(address) == old_value){
								Memory.writeS8(address, new_value);
							}
						}
					}
					else{
						if (bits == 64){
							if (Memory.readU64(address) == old_value){
								Memory.writeU64(address, new_value);
							}
						}
						else if (bits == 32){
							if (Memory.readU32(address) == old_value){
								Memory.writeU32(address, new_value);
							}
						}
						else{
							if (Memory.readU8(address) == old_value){
								Memory.writeU8(address, new_value);
							}
						}
					}
				},
				onError: function(reason){
					//console.log('[!] There was an error scanning memory:' + reason);
				},
				onComplete: function(){}
			});
		}
""" % (pattern, old_value, new_value, signed, bits))

	script.on('message', on_message)
	script.load()
	time.sleep(3)
	session.detach()

def get_pattern(number, isLittleEndian):
	hex_string = '{:02x}'.format(number)
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
	return pattern

def get_byte_array(number, isLittleEndian, bits, signed):
	pattern = get_pattern(number, isLittleEndian)
	if isLittleEndian:
		if len(pattern) < int(bits/8):
			for x in range(int(bits/8) - len(pattern)):
				pattern = pattern + '00'
	else:
		if len(pattern) < int(bits/8):
			for x in range(int(bits/8) - len(pattern)):
				pattern = '00' + pattern
	byte_array = []
	for byte in pattern:
		byte_array.append(int('0x' + byte, 16))
	if signed and number < 0:
		pass
	return byte_array

if __name__ == '__main__':
	argc = len(sys.argv)
	if argc < 5 or argc > 7:
		usage = 'Usage: {} (-U) (little|big) <64|32|8> <-s|-u> <process name or PID> <old value> <new value>\n'.format(__file__)
		usage += 'The -U option is for mobile instrumentation.\n'
		usage += 'Use the little (default) or big parameter to specify the endiannes.\n'
		usage += 'Specify the size of the variable in bits with 64, 32 or 8.\n'
		usage += 'Specify if the variable is signed or unsigned with -s or -u.\n'
		usage += 'Old value is the number to be replace with new value.'
		sys.exit(usage)

	usb = sys.argv[1] == '-U' or sys.argv[2] == '-U'
	isLittleEndian = sys.argv[1] != 'big' and sys.argv[2] != 'big'

	bits = int(sys.argv[argc - 5])
	if bits != 64 and bits != 32 and bits != 8:
		sys.exit('bad parameter')

	signed = sys.argv[argc - 4][1]
	if signed != 's' and signed != 'u':
		sys.exit('bad parameter')

	if sys.argv[argc - 3].isdigit():
		target_process = int(sys.argv[argc - 3])
	else:
		target_process = sys.argv[argc - 3]

	old_value = int(sys.argv[argc - 2])

	new_value = int(sys.argv[argc - 1])

	pattern = get_pattern(old_value, isLittleEndian)

	main(target_process, usb, pattern, old_value, new_value, signed, bits)

"""
escribir un byte array para cuando el sistema es big endian?
"""