#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
try:
	import frida
except ImportError:
	sys.exit('install frida\nsudo pip3 install frida')

def err(msg):
	sys.stderr.write(msg + '\n')

def on_message(message, data):
	if message['type'] == 'error':
		err('[!] ' + message['stack'])
	elif message['type'] == 'send':
		print('[+] ' + message['payload'])
	else:
		print(message)

def main():
	pathToCertificate = sys.argv[1]
	target_process = sys.argv[2]
	try:
		started = False
		session = frida.get_usb_device().attach(target_process)
	except frida.ProcessNotFoundError:
		print('Starting process {}...\n'.format(target_process))
		started = True
		device = frida.get_usb_device()
		try:
			pid = device.spawn([target_process])
		except frida.NotSupportedError:
			sys.exit('An error ocurred while attaching with the procces\n')
		session = device.attach(pid)

	script = session.create_script("""
/*
	code from:
	https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/
*/
Java.perform(function (){
	console.log("");
	console.log("[.] Cert Pinning Bypass/Re-Pinning");

	var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
	var FileInputStream = Java.use("java.io.FileInputStream");
	var BufferedInputStream = Java.use("java.io.BufferedInputStream");
	var X509Certificate = Java.use("java.security.cert.X509Certificate");
	var KeyStore = Java.use("java.security.KeyStore");
	var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	var SSLContext = Java.use("javax.net.ssl.SSLContext");

	// Load CAs from an InputStream
	console.log("[+] Loading our CA...")
	cf = CertificateFactory.getInstance("X.509");
	
	try {
		var fileInputStream = FileInputStream.$new("%s");
	}
	catch(err) {
		console.log("[o] " + err);
	}
	
	var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	var ca = cf.generateCertificate(bufferedInputStream);
	bufferedInputStream.close();

	var certInfo = Java.cast(ca, X509Certificate);
	console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

	// Create a KeyStore containing our trusted CAs
	console.log("[+] Creating a KeyStore for our CA...");
	var keyStoreType = KeyStore.getDefaultType();
	var keyStore = KeyStore.getInstance(keyStoreType);
	keyStore.load(null, null);
	keyStore.setCertificateEntry("ca", ca);
	
	// Create a TrustManager that trusts the CAs in our KeyStore
	console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	tmf.init(keyStore);
	console.log("[+] Our TrustManager is ready...");

	console.log("[+] Hijacking SSLContext methods now...")
	console.log("[-] Waiting for the app to invoke SSLContext.init()...")

	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
		console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
		console.log("[+] SSLContext initialized with our custom TrustManager!");
	}
});
""" % pathToCertificate)
	script.on('message', on_message)
	print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	script.load()
	if started:
		device.resume(pid)
	input()
	session.detach()	

if __name__ == '__main__':
	if len(sys.argv) != 2:
		usage = 'usage {} <path to certificate in device> <process name or PID>\n'.format(__file__)
		usage += 'run \'frida-ps -U\' to list processes\n'
		sys.exit(usage)
	main()
