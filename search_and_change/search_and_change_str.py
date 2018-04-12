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

def main(target_process, pattern, old_string, new_string, usb):
	try:
		if usb:
			session = frida.get_usb_device().attach(target_process)
		else:
			session = frida.attach(target_process)
	except:
		sys.exit('An error ocurred while attaching with the procces')
	script = session.create_script("""

		function get_pattern(string) {
			var pattern = "";
			for (var char in string) {
				var byte = char.charCodeAt(0).toString(16);
				if (byte.length == 1) {
					byte = "0" + byte;
				}
				pattern = pattern + " " + byte;
			}
			return pattern.substring(1);
		}

		var ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: true});

		for (var i = 0, len = ranges.length; i < len; i++)
		{
			Memory.scan(ranges[i].base, ranges[i].size, '%s', {
				onMatch: function(address, size_str){
					var stringEncontrado = Memory.readUtf8String(address, size = size_str);
					if(stringEncontrado == '%s'){
						Memory.writeUtf8String(address, '%s');
					}
				},
				onError: function(reason){
					//console.log('[!] There was an error scanning memory:' + reason);
				},
				onComplete: function(){}
			});
		}
""" % (pattern, old_string, new_string))

	script.on('message', on_message)
	script.load()
	time.sleep(3)
	session.detach()

def get_pattern(string):
	pattern = ''
	for char in string:
		byte = str(hex(ord(char)))[2:]
		if len(byte) == 1:
			byte = '0' + byte
		pattern = pattern + ' ' + byte
	return pattern[1:]

if __name__ == '__main__':
	argc = len(sys.argv)
	if argc < 4 or argc > 5:
		usage = 'Usage: {} (-U) <process name or PID> <old string> <new string>'.format(__file__)
		usage += '\nThe -U option is for mobile instrumentation.'
		usage += '\nOld string is the utf-8 string to be replace with new string'
		sys.exit(usage)

	usb = sys.argv[2] == '-U'

	if sys.argv[argc - 3].isdigit():
		target_process = int(sys.argv[argc - 3])
	else:
		target_process = sys.argv[argc - 3]

	old_string = sys.argv[argc - 2]

	new_string = sys.argv[argc - 1]

	pattern = get_pattern(old_string)

	main(target_process, pattern, old_string, new_string, usb)
