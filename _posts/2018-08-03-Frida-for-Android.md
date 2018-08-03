---
layout: post
title: Frida for Android
---

On this post we'll see how to setup Frida for Android and how to develop basic instrumentation scripts.

<a href="#what-is-frida">What is Frida</a><br/>
<a href="#setup-frida-for-android">Setup Frida for Android</a><br/>
<a href="#python-skeleton---attach-to-a-process">Python skeleton - Attach to a process</a><br/>
<a href="#python-skeleton---spawn-a-process">Python skeleton - Spawn a process</a><br/>
<a href="#manipulate-function-arguments-and-return-value">Manipulate function arguments and return value</a><br/>

<br/>

## What is Frida

Frida is a tool which allow binary / process instrumentation.

<br/>

##### What is process instrumentation ?
It is the fact of hooking functions to change the program behavior. 

With instrumentation we can :
Add functions on the fly
Modify functions on the fly
Manage the memory (allocate data, scan, etc.)
Retrieve arguments passed to functions
Retrieve return values of functions

<br/>

## Setup frida for Android

##### Requirements
* Install python with pip
* Rooted android device or emulator

<br/>

##### Install Frida tools and python bindings on client (laptop)
```bash
$ sudo pip install frida-tools
$ sudo pip install frida
$ frida --version
12.0.8
```

<br/>

##### Install Frida server on android device or emulator

First download the frida server build which belongs to your architecture (ARM, x86, x64, etc.) for the exact same version of frida on your client: https://github.com/frida/frida/releases

Then issue the following commands:
```bash
$ wget https://github.com/frida/frida/releases/download/12.0.8/frida-server-12.0.8-android-x86.xz
$ unxz frida-server-12.0.8-android-x86.xz
$ adb push frida-server-12.0.8-android-x86 /data/local/tmp/frida-server
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
```

Frida server can also be start with options:
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

## Manipulate function arguments and return value

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

------------

##### 1 : subtitle
![test_request](/images/Capture du 2017-05-15 12-54-44.png)
<br/>

