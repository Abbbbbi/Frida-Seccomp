# -*- coding: utf-8 -*-
import codecs
import frida
import sys
import os
import time
import subprocess
import threading

package_name = sys.argv[1]
jscode = open("./handleSeccomp.js").read()
dir_path = ""

device = frida.get_device_manager().enumerate_devices()[-1]
print(device)

pending = []
sessions = []
scripts = []
event = threading.Event()

def on_spawned(spawn):
    print('on_spawned:', spawn)
    pending.append(spawn)
    event.set()

def spawn_added(spawn):
    event.set()
    if(spawn.identifier.startswith(package_name)):
        print('spawn_added:', spawn)
        session = device.attach(spawn.pid)
        subprocess.Popen(args="adb logcat --pid={} | grep seccomp > {}/{}_{}.log".format(spawn.pid, dir_path, package_name, spawn.pid), stdin=None, stdout=None,stderr=None, shell=True)
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        device.resume(spawn.pid)
        
def spawn_removed(spawn):
    print('spawn_added:', spawn)
    event.set()

def on_message(spawn, message, data):
    print('on_message:', spawn, message, data)
    
def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

device.on('spawn-added', spawn_added)
device.on('spawn-removed', spawn_removed)
device.on('child-added', on_spawned)
device.on('child-removed', on_spawned)
device.on('process-crashed', on_spawned)
device.on('output', on_spawned)
device.on('uninjected', on_spawned)
device.on('lost', on_spawned)
device.enable_spawn_gating()
event = threading.Event()
print('Enabled spawn gating')

pid = device.spawn([package_name])
dir_path = "{}_{}_{}".format(package_name ,pid,time.time())
os.makedirs(dir_path)
session = device.attach(pid)
print("[*] Attach Application {} pid:".format(package_name),pid)
subprocess.Popen(args="adb logcat --pid={} | grep seccomp > {}/{}_{}.log".format(pid, dir_path, package_name, pid), stdin=None, stdout=None,stderr=None, shell=True)
print("[*] Application onResume")
script = session.create_script(jscode)
script.on('message', on_message)
print('[*] Running Frida-Seccomp')
script.load()
device.resume(pid)
sys.stdin.read()