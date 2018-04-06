#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import frida
import re

def on_message(message, data):
	if message['type'] == 'error':
		print('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[i] ' + message['payload'])
	else:
		print(message)

def main(target_process, pattern, new_value):
	session = frida.attach(target_process)
	script = session.create_script("""
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
		var range;

		function processNext(){
			range = ranges.pop();
			if(!range){
				return;
			}
			Memory.scan(range.base, range.size, '%s', {
				onMatch: function(address, size){
						console.log('[+] Pattern found at: ' + address.toString());
						Memory.writeInt(address, '%d');
						console.log('[+] Changed to new_value');
					}, 
				onError: function(reason){
						console.log('[!] There was an error scanning memory');
					}, 
				onComplete: function(){
						processNext();
					}
				});
		}
		processNext();
""" % (pattern, new_value))

	script.on('message', on_message)
	script.load()
	input('[!] Press <Enter> to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print('Usage: {} <process name or PID> <old_value> <new value>'.format(__file__))
		sys.exit(1)

	if sys.argv[1].isdigit():
		target_process = int(sys.argv[1])
	else:
		target_process = sys.argv[1]

	hex_string = '{:02x}'.format(int(sys.argv[2]))
	if len(hex_string) % 2 == 1:
	        hex_string = '0' + hex_string
	lst = re.findall(r'.{2}', hex_string)
	hex_string = ''
	for elem in lst:
	        hex_string = hex_string + ' ' + elem
	pattern = hex_string[1:]
	
	new_value = int(sys.argv[3])
	
	main(target_process, pattern, new_value)
