#found in /usr/local/sbin/

import socket
import sys
import telnetlib
import paramiko
import subprocess
from subprocess import call, check_output, Popen, PIPE, STDOUT
import json
from paramiko.ssh_exception import AuthenticationException, SSHException, NoValidConnectionsError
import time
import string
import random
from itertools import izip
import nmap

def changePassword(ip, port, user, password):
	# generate a random password
	N = 12
	newPass = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))
	#print "random: "+ newPass

	#establish ssh connection
	if port == 22:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			# log onto device
			ssh.connect(ip, username=user, password=password)
			print "in here"
			# change the password of the device
			stdin, stdout, stderr = ssh.exec_command("passwd")
			stdin.write(password+'\n')
			stdin.write(newPass+'\n')
			stdin.write(newPass+'\n')
			stdin.flush()
			exit = 1
			return newPass
		except AuthenticationException:
			print "exception 1"
			return 0
	# elif port == 23:
	# 	# try to establish a telnet connection using a default username password combination
	# 	p = Popen(["telnet", "-l", user, ip],stdin=PIPE,stdout=PIPE,stderr=PIPE)
	
	# 	response = ""
	# 	while not "Password: " in response:
	# 		response += p.stdout.read(1)

	# 	p.stdin.write(password + '\n')
	# 	p.stdin.flush()

	# 	time.sleep(4)
	# 	response = p.stdout.readline()
	# 	# try next username password combination if this one did not work
	# 	#if "Login incorrect" in response:
	# 	if "login" in response:
	# 		#obj_json = {u"IPaddress":ip, u"port":23, u"defaultUsr":"N/A", u"defaultPass":"N/A", u"newPass":"N/A"}
	# 		obj_json = {ip:{u"port":23, u"defaultUsr":"N/A", u"defaultPass":"N/A", u"newPass":"N/A"}}
	# 		deviceList.append(obj_json)
	# 		#continue
	# 	# save info about devices with default username and password 	
	# 	else:
	# 		# log onto device
	# 		#ssh.connect(ip, username=user, password=password)
	# 		# change the password of the device
	# 		#stdin, stdout, stderr = p.exec_command("passwd")
	# 		#p = Popen(["passwd"])
	# 		#p.stdin.write("passwd"+'\n')
	# 		#time.sleep(4)
	# 		print "password:" + newPass
	# 		pp = Popen(["echo", "hello"],stdin=PIPE,stdout=PIPE,stderr=PIPE) #p.stdin.write(password+'\n')
	# 		p.stdin.write(newPass+'\n')
	# 		p.stdin.write(newPass+'\n')
	# 		p.stdin.flush()
	# 		#print "try"
	# 		return newPass

def main():
	
	ports = open('ports.txt', 'r') # testing with only 22 or 23 on there
	userpass = open('defuserpass.txt', 'r') # actual file
	#userpass = open('testpass.txt', 'r') # for testing
	successes = open('success.txt', 'w')
	deviceList = []

	# construct a dictionary with functions (case/switch)
	def ssh(ip):
		#for all IP addresses found on network:
		#exit = 0 # to keep track of when to stop trying password combinations if already successful
		userpass = open('testpass.txt', 'r')
		success = 0
		for line in userpass:
			if success == 1:
				break
			# parse device info
			y = line.split('\t')
			user = y[0].strip() # possible username
			passw = y[1].strip() # possible password

			# try to establish ssh connection using default username password combination
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			try:
				print "user: "+user
				print "password: "+passw
				ssh.connect(ip, username=user, password=passw)
			except AuthenticationException:
				print "Caught an Authentication Exception"
				continue
			except SSHException:
				print "Caught an SSHException"
				continue
			except NoValidConnectionsError:
				print "Unable to connect to port 22 on this device"
				break

			time.sleep(4)

			# save info about devices with default username and password 	
			successes.write(ip + '\t' + user + '\t' + passw.strip() + '\t' + '22' + '\n')
			successes.close()

			devices = open('success.txt', 'r')
			# go through all devices with default username and password
			for device in devices:
				# set exit to 1 to know to stop trying default login credentials
				success = 1
				# parse the info about the device
				x = device.split('\t')
				correctIP = x[0] # IP address of device
				correctUsr = x[1] # Default username of device
				correctPass = x[2] # Default password of device

				newPass = changePassword(correctIP, 22, correctUsr, correctPass)

				obj_json = {ip:{u"port":22, u"defaultUsr":user, u"defaultPass":passw, u"newPass":newPass}}
				deviceList.append(obj_json)

			devices.close()
		# If no default username and password combination detected, write this out:
		if success == 0:
			obj_json = {ip:{u"port":22, u"defaultUsr":"N/A", u"defaultPass":"N/A", u"newPass":"N/A"}}
			deviceList.append(obj_json)
		userpass.close()

	def telnet(ip):
		userpass = open('testpass.txt', 'r')
		successes = open('success.txt', 'w')
		HOST = ip
		#for ip in IPaddresses:
		success = 0
		for line in userpass:
			if success == 1:
				break
			# parse device info
			y = line.split('\t')
			user = y[0].strip()
			password = y[1].strip()

			print "user: " + user
			# try to establish a telnet connection using a default username password combination
			p = Popen(["telnet", "-l", user, HOST],stdin=PIPE,stdout=PIPE,stderr=PIPE)

			response = ""
			while not "Password: " in response:
				response += p.stdout.read(1)
				print response

			time.sleep(2)
			p.stdin.write(password+'\n')
			p.stdin.flush()

			time.sleep(6)
			response = p.stdout.read(19)
			print "RESPONSE: " + response
			# try next username password combination if this one did not work
			if "Login incorrect" in response:
				print "WRONG LOGIN"
				continue
			# save info about devices with default username and password 	
			else:
				success = 1
				successes.write(ip + '\t' + user + '\t' + password.strip() + '\t' + '23' + '\n')
				successes.close()

			devices = open('success.txt', 'r')

			# go through all devices with default username and password
			for device in devices:
				# parse device information
				x = device.split('\t')
				correctIP = x[0]
				correctUsr = x[1]
				correctPass = x[2]

				newPass = changePassword(correctIP, 23, correctUsr, correctPass)
				
				if newPass != 0:
					obj_json = {ip:{u"port":23, u"defaultUsr":user, u"defaultPass":password, u"newPass":newPass}}
					deviceList.append(obj_json)
				else:
					obj_json = {ip:{u"port":23, u"defaultUsr":"N/A", u"defaultPass":"N/A", u"newPass":"N/A"}}
					deviceList.append(obj_json)

			devices.close()
		if success == 0:
			obj_json = {ip:{u"port":23, u"defaultUsr":"N/A", u"defaultPass":"N/A", u"newPass":"N/A"}}
			deviceList.append(obj_json)

		userpass.close()

	options = {22 : ssh,
				23 : telnet,
	}

	for p in ports:

		if p.strip() == '22':
			nmap_ssh = open('nmapSSH.txt', 'w')
		elif p.strip() == '23':
			nmap_telnet = open('nmapTelnet.txt', 'w')

		# find IP address of current device
		inetAddress = check_output(["ifconfig", "en0", "inet"])
		parsed = inetAddress.split()
		# Extract IP address
		ipParsed = parsed[5].split('.')
		# IP address of current device as a string
		finalIP = ipParsed[0]+'.'+ipParsed[1]+'.'+ipParsed[2]+'.'+ipParsed[3]
		# IP address range based on the IP address of the current device
		finalIPrange = ipParsed[0]+'.'+ipParsed[1]+'.'+ipParsed[2]+'.0/24'
	
		# Scan network using nmap on the specified IP range on ports 22 or 23
		nm = nmap.PortScanner()
		host = nm.scan(finalIPrange, p)
		hosts = nm.all_hosts() # get all hosts that were scanned (including the current machine)

		for host in hosts:
			# to prevent that they try to change the password of the current device, keep?
			if host != finalIP:
				if p.strip() == '22':
					nmap_ssh.write(host+'\n')
				elif p.strip() == '23':
					nmap_telnet.write(host+'\n')
		if p.strip() == '22':
			nmap_ssh.close()
		if p.strip() == '23':
			nmap_telnet.close()

		# go through the IP addresses found on the network within the specified range
		if p.strip() == '22':
			sshDevices = open('nmapSSH.txt', 'r')
			for ip in sshDevices:
				print "outchere"
				options[22](ip.strip())
		elif p.strip() == '23':
			telnetDevices = open('nmapTelnet.txt', 'r')
			for ip in telnetDevices:
				options[23](ip.strip())

	# call dumps on the whole list of all devices
	print json.dumps(deviceList)

	ports.close()
	userpass.close()
	successes.close()

main()
