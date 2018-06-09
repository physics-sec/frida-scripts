## Frida tools

This repository contains several scripts that implement Frida for multiple purposes.

### examples

A small collection of programs that use frida in very simple ways.

### search_and_change

It consist of two scripts, they look for a number or string in a process and replace it with whatever the user wants. Works for Windows, linux, Android and IOS.

### Android

#### URL

Shows which URLs are accessed by the app using `new URL('https://www.foo.com')`.

#### certificatePinning

This script bypassing certificate-pinning and forces an app to use an user supplied certificate. This way is possible to proxy the app's traffic.
code by: [Piergiovanni Cipolloni](https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/) 
 
#### getLoadedClasses

A simple script that shows what classes are imported by the app.

#### httpGet

A program that shows GET requests and their response.
code by: [Keith](https://stackoverflow.com/questions/46711786/android-hooking-https-traffic-using-frida)

