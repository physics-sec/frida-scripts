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

def main(target_process, pattern, old_string, new_string):
	try:
		session = frida.attach(target_process)
	except:
		sys.exit('The process does not exist')
	script = session.create_script("""
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

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print('Usage: {} <process name or PID> <old string> <new string>'.format(__file__))
		sys.exit(1)

	if sys.argv[1].isdigit():
		target_process = int(sys.argv[1])
	else:
		target_process = sys.argv[1]

	old_string = sys.argv[2]

	new_string = sys.argv[3]

	pattern = ''
	for char in old_string:
		byte = str(hex(ord(char)))[2:]
		if len(byte) == 1:
			byte = '0' + byte
		pattern += ' ' + byte
	pattern = pattern[1:]
	
	main(target_process, pattern, old_string, new_string)
