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

def main(target_process, usb, old_value, new_value, endianness, signed, bits):
	try:
		if usb:
			session = frida.get_usb_device().attach(target_process)
		else:
			session = frida.attach(target_process)
	except:
		sys.exit('An error ocurred while attaching with the procces')
	script = session.create_script("""
		function get_pattern(number, isLittleEndian, bits, signed) {
			var fixFistBit = (number < 0 && signed == "s");
			number = parseInt(number);

			var hex_string = number.toString(16);
			if (hex_string.length %% 2 == 1) {
				hex_string = '0' + hex_string;
			}
			var pattern = "";
			hex_string.match(/.{2}/g).forEach(function(byte) {
				if (isLittleEndian) {
					pattern = byte + " " + pattern;
				}
				else {
					pattern = pattern + " " + byte;
				}
			});
			if (isLittleEndian) {
				pattern = pattern.substring(0, pattern.length - 1);
			}
			else {
				pattern = pattern.substr(1);
			}

			var cantBytes = pattern.split(" ").length;
			var bytesReg = Math.floor(bits/8);
			for (i = 0; i < (bytesReg - cantBytes); i++) {
				pattern = (isLittleEndian ? pattern + ' 00' : '00 ' + pattern);
			}
			var lenPattern = pattern.length;
			if (fixFistBit) {
				if (isLittleEndian) {
					var prev = pattern.substring(lenPattern-1, lenPattern);
					var nvo = parseInt(prev);
					nvo |= 256;
					nvo = nvo.toString();
					pattern = pattern.substring(0, lenPattern-1) + nvo;
				}
				else {
					var prev = pattern.substring(0, 2);
					var nvo = parseInt(prev);
					nvo |= 256;
					nvo = nvo.toString();
					pattern = nvo + pattern.substring(2);
				}
			}
			return pattern;
		}

		function get_byte_array(number, isLittleEndian, bits, signed) {
			var pattern = get_pattern(number, isLittleEndian, bits, signed);
			console.log("[i] will write: " + pattern);
			var byte_array = [];
			var bytes = pattern.split(" ");
			for (var i = bytes.length - 1; i >= 0; i--) {
				byte_array.push(parseInt("0x" + bytes[i]));
			}
			return byte_array;
		}		
		var old_value = %d;
		var new_value = %d;
		var isLittleEndian = '%s' == "l";
		var signed = '%s';
		var bits = %d; //64, 32 or 8
		var pattern = get_pattern(old_value, isLittleEndian, bits, signed);
		var byte_array = get_byte_array(new_value, isLittleEndian, bits, signed);

		var ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: true});
		console.log("[i] searching for " + pattern);
		for (var i = 0, len = ranges.length; i < len; i++)
		{
			Memory.scan(ranges[i].base, ranges[i].size, pattern, {
				onMatch: function(address, size) {
					console.log("[i] found at " + address);
					Memory.writeByteArray(address, byte_array.reverse());
				},
				onError: function(reason) {
					//console.log('[!] There was an error scanning memory:' + reason);
				},
				onComplete: function(){
					//
				}
			});
		}
""" % (old_value, new_value, endianness, signed, bits))

	script.on('message', on_message)
	script.load()
	time.sleep(3)
	session.detach()

if __name__ == '__main__':
	argc = len(sys.argv)
	if argc < 5 or argc > 7:
		usage = 'Usage: {} (-U) (little|big) <64|32|16|8> <-s|-u> <process name or PID> <old value> <new value>\n'.format(__file__)
		usage += 'The -U option is for mobile instrumentation.\n'
		usage += 'Use the little (default) or big parameter to specify the endiannes.\n'
		usage += 'Specify the size of the variable in bits with 64, 32 or 8.\n'
		usage += 'Specify if the variable is signed or unsigned with -s or -u.\n'
		usage += 'Old value is the number to be replace with new value.'
		sys.exit(usage)

	usb = sys.argv[1] == '-U' or sys.argv[2] == '-U'
	isLittleEndian = sys.argv[1] != 'big' and sys.argv[2] != 'big'
	endianness = 'l' if (sys.argv[1] != 'big' and sys.argv[2] != 'big') else 'b'

	bits = int(sys.argv[argc - 5])
	if bits != 64 and bits != 32 and bits != 16 and bits != 8:
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

	main(target_process, usb, old_value, new_value, endianness, signed, bits)
