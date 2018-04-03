#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import frida
import time

def on_message(message, data):
	if message['type'] == 'error':
		print('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[i] ' + message['payload'])
	else:
		print(message)

def main(target_process):
	session = frida.attach(target_process)
	script = session.create_script("""
		Process.enumerateModules({
			onMatch: function(module){
				console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
			}, 
			onComplete: function(){}
		});
""")

	script.on('message', on_message)
	script.load()
	time.sleep(2)
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Usage: {} <process name or PID>'.format(__file__))
		sys.exit(1)

	if sys.argv[1].isdigit():
		target_process = int(sys.argv[1])
	else:
		target_process = sys.argv[1]
	
	main(target_process)
