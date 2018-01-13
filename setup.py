#!/usr/bin/env python2.7
import subprocess, re, telnetlib

#Create a class to hold host information. I considered using a dictionary but it's easier to edit class variables
class Host:
	def __init__(self, IP, service, user, passwd):
		self.IP = IP
		self.service = service
		self.user = user
		self.passwd = passwd
		self.processed = False

#First I need to nmap to get the hosts.gnmap file.
print "Nmapping network"
nmap_command = "nmap -oA hosts 192.168.1.0/24"
nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, shell=True)
nmap_output, nmap_error = nmap_process.communicate()

#Now feed the users and passwords to brutespray.
#Somehow store the service, host, username, and password together.
#Python can be used in this script because it is on the setup device which should have no trouble with python.
print "Bruteforcing devices"
brutespray_command = "brutespray --file hosts.gnmap --service ssh,telnet --threads 3 --hosts 5 -U users.txt -P passwords.txt | grep 'ACCOUNT FOUND'"
brutespray_process = subprocess.Popen(brutespray_command, stdout=subprocess.PIPE, shell=True)
brutespray_output, brutespray_error = brutespray_process.communicate()

#The way subprocess works means that all of the chars have to be joined together before the output can be split into lines which is what I actually want to process
output_as_list = []
for aChar in brutespray_output:
	output_as_list.append(aChar)
real_output = ''.join(output_as_list).split('\n')

#Create the host objects for the next for loop
print "Processing hosts"
hosts = []
for line in real_output:
	if line:
		anIP = line.split()[4]
		aService = line.split()[2]
		aUser = line.split()[6]
		aPass = line.split()[8]
		aHost = Host(anIP, aService, aUser, aPass)
		print "Destination: {IP}, Service: {service}, User: {user}, Password: {password}".format(IP=anIP, service=aService, user=aUser, password=aPass)
		hosts.append(aHost)

#I should make sure there aren't any duplicates in the hosts list. I should allow multiple of the same IPs but only one of each service.

#TODO: Check to see if I actually need to use shell=True
#TODO: Check to see if I actually need to use stdout=subprocess.PIPE
def doSSH(host, newuser, newpass):
	#TODO: Store new user/pass combo
	#TODO: Error checking
	#TODO: Print statements to say whats going on
	#TODO: If Telnet exists then it should be disabled. This should be done with an iptables command to drop all traffic bound for port 23 (done but untested)

	host.processed = True
	print "{IP}: Transferring install script".format(IP=host.IP)
	transfer_install_command = "cat honeypot_install.sh | sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'cat > honeypot_install.sh'".format(passwd=host.passwd, user=host.user, IP=host.IP)
	transfer_install_process = subprocess.Popen(transfer_install_command, stdout=subprocess.PIPE, shell=True)
	transfer_install_process.wait() #This wait ensures that the process finishes before we try to communicate. Else we break the pipe.
	transfer_install_output, transfer_install_error = transfer_install_process.communicate()

	print "{IP}: Transferring report script".format(IP=host.IP)
	transfer_report_command = "cat report.py | sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'cat > report.py'".format(passwd=host.passwd, user=host.user, IP=host.IP)
	transfer_report_process = subprocess.Popen(transfer_report_command, stdout=subprocess.PIPE, shell=True)
	transfer_report_process.wait() #This wait ensures that the process finishes before we try to communicate. Else we break the pipe.
	transfer_report_output, transfer_report_error = transfer_report_process.communicate()

	print "{IP}: Running install script".format(IP=host.IP)
	setup_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'chmod +x honeypot_install.sh && ./honeypot_install.sh'".format(passwd=host.passwd, user=host.user, IP=host.IP)
	setup_process = subprocess.Popen(setup_command, stdout=subprocess.PIPE, shell=True)
	setup_process.wait()
	setup_output, setup_error = setup_process.communicate()

	print "{IP}: Adding new user {anewuser}".format(IP=host.IP, anewuser=newuser)
	#newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo adduser --gecos "" --disabled-password {anewuser} && echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
	newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo adduser --gecos "" --disabled-password {anewuser}'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser)
	newuser_process = subprocess.Popen(newuser_command, stdout=subprocess.PIPE, shell=True)
	newuser_process.wait()
	newuser_output, newuser_error = newuser_process.communicate()

	print "{IP}: Changing new user {anewuser} password".format(IP=host.IP, anewuser=newuser)
	#newpass_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
	newpass_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
	newpass_process = subprocess.Popen(newpass_command, stdout=subprocess.PIPE, shell=True)
	newpass_process.wait()
	newpass_output, newpass_error = newpass_process.communicate()

	print "{IP}: Disabling old user".format(IP=host.IP)
	deluser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo passwd -l {user}'".format(passwd=host.passwd, user=host.user, IP=host.IP)
	deluser_process = subprocess.Popen(deluser_command, stdout=subprocess.PIPE, shell=True)
	deluser_process.wait()
	deluser_output, deluser_error = deluser_process.communicate()

	#disable_telnet_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'iptables -A INPUT -p tcp -m tcp --dport 23 -j DROP'".format(passwd=host.passwd, user=host.user, IP=host.IP)
	#disable_telnet_process = subprocess.Popen(disable_telnet_command, stdout=subprocess.PIPE, shell=True)
	#disable_telnet_process.wait()
	#disable_telnet_output, disable_telnet_error = disable_telnet_process.communicate()

def doTelnet(host):
	#The other end is going to need to use netcat which I think is a decent assumption
	#Essentially here I am going to have the device setup ssh and disable telnet for security reasons. TinySSH might be best here.
	#Once ssh is set up then the ssh configuration should take place
	host.processed = True
	telnet_transfer_command = ""
	tn = telnetlib.Telnet(host.IP)

	tn.read_until("login: ")
	tn.write(host.user + "\n")
	if password:
		tn.read_until("Password: ")
		tn.write(host.passwd + "\n")

	tn.write("ls\n")
	tn.write("exit\n")

#Now loop through the addresses and their respective protocol (telnet or ssh).
print "Looping through hosts"
for host in hosts:
	#Run the honeypot setup script on the remote system.
	#TODO: Need to make sure that if a host has the ability to use ssh then it is. Basically, telnet should be a last resort
	#TODO: Make the Telnet if statement call doSSH after doTelnet sets up the ssh client.
	#TODO: Somehow doSSH needs to take in a new user and password. Perhaps this whole file should have arguments for one master user and password combo, procedural generation, or manual input
	if host.service == "[ssh]" and host.processed == False:
		#doSSH(host, "test", "test")
		print "{IP}: Creating encrypted password".format(IP=host.IP)
		pass_command = "echo test | openssl passwd -1 -stdin"
		pass_process = subprocess.Popen(pass_command, stdout=subprocess.PIPE, shell=True)
		pass_process.wait()
		pass_output, pass_error = pass_process.communicate()
		print pass_output

		# print "{IP}: Adding new user test".format(IP=host.IP)
		# #newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo adduser --gecos "" --disabled-password {anewuser} && echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
		# newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'sudo useradd -m -s /bin/bash -p {encpass} test'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		# newuser_process = subprocess.Popen(newuser_command, stdout=subprocess.PIPE, shell=True)
		# newuser_process.wait()
		# newuser_output, newuser_error = newuser_process.communicate()

		# print "{IP}: Adding new user test".format(IP=host.IP)
		# #newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo adduser --gecos "" --disabled-password {anewuser} && echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
		# newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'sudo adduser --gecos "" --disabled-password test'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		# newuser_process = subprocess.Popen(newuser_command, stdout=subprocess.PIPE, shell=True)
		# newuser_process.wait()
		# newuser_output, newuser_error = newuser_process.communicate()

		# print "{IP}: Changing new user test password".format(IP=host.IP)
		# #newpass_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
		# newpass_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'echo test:test | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		# newpass_process = subprocess.Popen(newpass_command, stdin=subprocess.PIPE, shell=True)
		# #newpass_process.wait()
		# newpass_output, newpass_error = newpass_process.communicate("test:test")

	if host.service == "[telnet]" and host.processed == False:
		doTelnet(host)
		#doSSH(host, "test", "test")
