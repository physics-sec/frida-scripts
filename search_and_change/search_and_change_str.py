#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
try:
	import frida
except ImportError:
	sys.exit('install frida\nsudo pip3 install frida')

def on_message(message, data):
	if message['type'] == 'error':
		print('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[i] ' + message['payload'])
	else:
		print(message)

def main(target_process, old_string, new_string, usb, mode, testing):
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

		function get_byte_array(string) {
			var pattern = get_pattern(string);
			var byte_array = [];
			var bytes = pattern.split(" ");
			for (var i = 0; i < bytes.length; i++) {
				byte_array.push(parseInt("0x" + bytes[i]));
			}
			return byte_array;
		}

		var old_str = '%s';
		var new_str = '%s';
		var mode = '%s';
		var testing = '%s' == "y";
		var pattern = get_pattern(old_str);
		var new_pattern = get_pattern(new_str);
		var byte_array = get_byte_array(new_str);

		console.log("[i] searching for " + pattern);
		if (testing) {
			console.log("[i] nothing will be written");
		}
		else {
			console.log("[i] replacing for " + new_pattern);
		}
		console.log("")

		var ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: true});

		for (var i = 0, len = ranges.length; i < len; i++) {
			Memory.scan(ranges[i].base, ranges[i].size, pattern, {
				onMatch: function(address, size_str) {
					if (testing) {
						console.log("[+] found at " + address);
					}
					else {
						console.log("[+] hit at " + address);
						if (mode == "string") {
							Memory.writeUtf8String(address, new_str);
						}
						else {
							Memory.writeByteArray(address, byte_array);
						}						
					}
				},
				onError: function(reason) {
					//console.log('[!] There was an error scanning memory:' + reason);
				},
				onComplete: function() {
					//
				}
			});
		}
""" % (old_string, new_string, mode, testing))

	script.on('message', on_message)
	print('[i] Press <Enter> at any time to detach from instrumented program.\n')
	script.load()
	input()
	session.detach()

if __name__ == '__main__':
	argc = len(sys.argv)
	if argc < 4 or argc > 7:
		usage = 'Usage: {} [-U] [-n] [-t] <process name or PID> <old string> <new string>'.format(__file__)
		usage += '\nThe -U option is for mobile instrumentation.'
		usage += '\nThe -n option is to write a null-terminated string.'
		usage += 'The \'-t\' option is for testing. Matches will be shown but nothing will be written.\n'
		sys.exit(usage)

	usb = False
	mode = 'array'
	testing = 'n'
	for i in range(1, argc - 3):
		if sys.argv[i] == '-U':
			usb = True
		elif sys.argv[i] == '-n':
			mode = 'string'
		elif sys.argv[i] == '-t':
			testing = 'y'

	if sys.argv[argc - 3].isdigit():
		target_process = int(sys.argv[argc - 3])
	else:
		target_process = sys.argv[argc - 3]

	old_string = sys.argv[argc - 2]

	new_string = sys.argv[argc - 1]

	main(target_process, old_string, new_string, usb, mode, testing)
