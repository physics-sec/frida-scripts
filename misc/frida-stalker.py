#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import frida

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
function StalkerExeample() 
{
	var threadIds = [];

	Process.enumerateThreads({
		onMatch: function (thread) 
		{
			threadIds.push(thread.id);
			console.log("Thread ID: " + thread.id.toString());
		},

		onComplete: function () 
		{
			threadIds.forEach(function (threadId) 
				{
					Stalker.follow(threadId, 
					{
						events: {call: true},
					
					onReceive: function (events)
					{
						console.log("onReceive called.");
					},
					onCallSummary: function (summary)
					{
						console.log("onCallSummary called.");
					}
				});
			});
		}
	});
}

StalkerExeample();
""")
	script.on('message', on_message)
	script.load()
	input('[!] Press <Enter> to detach from instrumented program.\n\n')
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
