## Frida tools

This repository contains several scripts that implement Frida for multiple purposes.

### Check the *Wiki* for script templates!
___
### examples

A small collection of programs that use frida in very simple ways.

### search_and_change

It consist of two scripts, they look for a number or string in a process and replace it with whatever the user wants. Works for Windows, linux, Android and IOS.

### Android

Most of the scripts on this folder are a work in progress. PRs are welcome.

#### URL

Shows which URLs are accessed by the app using `new URL('https://www.foo.com')`.

#### certificatePinning

This script can be use for bypassing certificate-pinning and force an app to use a user-supplied SSL certificate. Once this is done, it should be possible to proxy all the app's traffic.

code by: [WooyunDota](https://github.com/WooyunDota/DroidSSLUnpinning) 
 
#### getLoadedClasses

A simple script that shows what classes are imported by the app.

#### httpGetPost

A program that shows GET and POST requests and their responses.

code by: [Keith](https://stackoverflow.com/questions/46711786/android-hooking-https-traffic-using-frida)

### misc

A collection of scripts that facilitates information gathering.

code by: [poxyran](https://github.com/poxyran/misc)

