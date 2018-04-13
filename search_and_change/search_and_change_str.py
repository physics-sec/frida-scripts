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

def main(target_process, old_string, new_string, usb):
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
			for (var i = 0; i < string.length; i++) {
				var byte = string[i].charCodeAt(0).toString(16);
				if (byte.length == 1) {
					byte = "0" + byte;
				}
				pattern = pattern + " " + byte;
			}
			return pattern.substring(1);
		}

		var old_str = '%s';
		var new_str = '%s';
		var pattern = get_pattern(old_str);
		var new_pattern = get_pattern(new_str);

		console.log("[i] searching for " + pattern);
		console.log("[i] replacing for " + new_pattern);

		var ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: true});

		for (var i = 0, len = ranges.length; i < len; i++)
		{
			Memory.scan(ranges[i].base, ranges[i].size, pattern, {
				onMatch: function(address, size_str) {
					console.log("[i] found at " + address);
					Memory.writeUtf8String(address, new_str);
				},
				onError: function(reason) {
					//console.log('[!] There was an error scanning memory:' + reason);
				},
				onComplete: function() {
					//
				}
			});
		}
""" % (old_string, new_string))

	script.on('message', on_message)
	script.load()
	time.sleep(3)
	session.detach()

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

	main(target_process, old_string, new_string, usb)
