---
layout: post
title: Frida for Android
---

On this post we'll see how to setup Frida for Android and how to develop basic instrumentation scripts.

<a href="#what-is-frida">What is Frida ?</a><br/>
<a href="#setup-frida-for-android">Setup Frida for Android</a><br/>
<a href="#python-skeleton---attach-to-a-process">Python skeleton - Attach to a process</a><br/>
<a href="#python-skeleton---spawn-a-process">Python skeleton - Spawn a process</a><br/>
<a href="#hook-java-code">Hook java code</a><br/>
<a href="#hook-native-code">Hook native code</a><br/>
<a href="#hook-native-code-using-offset">Hook native code using offset</a><br/>

<br/>

## What is Frida ?

It’s Greasemonkey for native apps, or, put in more technical terms, it’s a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, Android, and QNX. Frida also provides you with some simple tools built on top of the Frida API.

Frida’s core is written in C and injects Google’s V8 engine into the target processes, where your JS gets executed with full access to memory, hooking functions and even calling native functions inside the process. There’s a bi-directional communication channel that is used to talk between your app and the JS running inside the target process.

What can we do with dynamic code instrumentation ?

- Add functions on the fly
- Modify functions on the fly
- Manage the memory (allocate/overwrite data, scan, etc.)
- Retrieve arguments passed to functions
- Retrieve return values of functions

More information can be found on <a href="https://www.frida.re/">Frida website</a>.

<br/>

## Setup frida for Android

##### Requirements
* Python with pip
* Rooted android device or emulator


##### Install Frida tools and python bindings on client
```bash
$ sudo pip install frida-tools
$ sudo pip install frida
$ frida --version
12.0.8
```

##### Install Frida server on android device or emulator

First download the frida server build which belongs to your Android device architecture (ARM, x86, x64, etc.) with the exact same version as frida installed on your client: <a>https://github.com/frida/frida/releases</a>

Then issue the following commands:
```bash
$ wget https://github.com/frida/frida/releases/download/12.0.8/frida-server-12.0.8-android-x86.xz
$ unxz frida-server-12.0.8-android-x86.xz
$ adb push frida-server-12.0.8-android-x86 /data/local/tmp/frida-server
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
```

Frida server can also be started with options:
```bash
# listen on 127.0.0.1:27042 (the default)
$ frida-server

# listen on all interfaces
$ frida-server -l 0.0.0.0

# listen on a specific interface
$ frida-server -l 192.168.1.3

# listen on a specific interface and port
$ frida-server -l 192.168.1.3:1337
```

<br/>

## Python skeleton - Attach to a process

```python
#!/usr/bin/python

'''
Frida Android Skeleton - Attach to process
'''

import frida
import sys

# Define callback function to receive and output messages from server
def get_messages_from_js(message, data):
   print(message)
   print(data)


# Define the application to hook
app = 'com.test.myapp'

hook_code = '''
        
        /*  Javascript code to manipulate the process  */

'''

# get connect to frida server through emulator and attach to process
session = frida.get_usb_device().attach(app)

# create script using hook_code variable above
script = session.create_script(hook_code)

# setup callback using function defined above
script.on('message', get_messages_from_js)

# load script into the process
script.load()

# read from stdin to keep script running
sys.stdin.read()

sys.exit(0)
```
<br>

## Python skeleton - Spawn a process

```python
#!/usr/bin/python

'''
Frida Android Skeleton - Spawn the process
'''

import frida
import sys

# define callback function to receive and output messages from server
def get_messages_from_js(message, data):
   print(message)
   print(data)


# define the application to hook
app = 'com.test.myapp'

hook_code = '''
        
        /*  Javascript code to manipulate the process  */

'''

device = frida.get_usb_device()

# spawn the process
p1 = device.spawn([app])

# attach to the process
process = device.attach(p1)

# create script using hook_code variable above
script = process.create_script(hook_code)

# setup callback using function defined above
script.on('message',get_messages_from_js)

# load script into the process
script.load()

# Avoid app to freeze
device.resume(p1)

# read from stdin to keep script running
sys.stdin.read()

```

<br>

## Hook java code

In the following script we will log arguments and return value of a function and modify them on the fly.

```python
hook_code = """
       
// prevent timeout
setImmediate(function() {
        console.log("[*] Starting script - Log / Manipulate args and retval");
	
	// ask java to execute code
        Java.perform(function() {   
            myClass = Java.use("com.test.myapp.sslpinning.PinningManager");
            myClass.checkServerTrusted.implementation = function(a, b) {
		
		// log original args and retval
		console.log('Original Arg1 ==> ' + a);
		console.log('Original Arg2 ==> ' + b); 
                retval = this.checkServerTrusted(a, b);
		console.log('Original Retval ==> ' + retval);

		// modify args and retval
		a = 'tata !';
		console.log('\nModified Arg1 ==> ' + a);
		b = 'SSL Pinning is awesome !!';
		console.log('Modified Arg2 ==> ' + b);
		retval = 'Retval is overwritten now...';
		console.log('Modified retval ==> ' + retval);
		return;
           }               
            console.log("[*] SSL pinning handler modified");
        });
});
"""
```

<br>

## Hook native code

```python
hook_code = """

Interceptor.attach(Module.findExportByName("libchallenge.so", "fopen"), {

	onEnter: function (args) {
    		file = Memory.readUtf8String(args[0]);
	    	pattern = "busybox";

       		// Replace /proc/self/maps with a legit output
	        if(file == '/proc/self/maps') {
        	    	newFile = Memory.allocUtf8String('/data/local/tmp/legit_proc_self_maps'); 
            		args[0] = newFile; 
	            	console.log("[+] fopen : /proc/self/maps modified");	
        	}

	        // Replace files used for root detection
        	if((file == '/sbin/su') || (file.indexOf(pattern) !== -1)) {
        		newFile = Memory.allocUtf8String('/sbin/idonotexist');
	        	args[0] = newFile;
        		console.log("[+] fopen : " + file + " modified");
	        }        	
	},
    
    	onLeave: function (retval) {
    	}
	
});
"""
```

<br>

## Hook native code using offset

```python
hook_code = """
    
console.log("[*] Starting script");
console.log('libchallenge base address : ' + Module.findBaseAddress('libchallenge.so'));

Interceptor.attach(Module.findBaseAddress("libchallenge.so").add('0x4321'),  {
            
	onEnter: function (args) {
		this.fileDescriptor = args[0];
	        console.log(Memory.readUtf8String(this.fileDescriptor));
      	},
            
	onLeave: function (retval) {
                console.log(retval);
        }   
});
"""
```

