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
hosts = []
for line in real_output:
	if line:
		anIP = line.split()[4]
		aService = line.split()[2]
		aUser = line.split()[6]
		aPass = line.split()[8]
		aHost = Host(anIP, aService, aUser, aPass)
		hosts.append(aHost)

def doSSH(host):
		#I need to create a new user and password here as well. This needs to also be stored.
		#The port change for administration is done in the honeypot install
		#TODO: Create a new root user/pass combo
		#TODO: Disable the root account and delete it if possible.
		#TODO: Transfer the report.py file

		host.processed = True
		ssh_transfer_command = "cat honeypot_install.sh | sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'cat > honeypot_install.sh'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		ssh_transfer_process = subprocess.Popen(ssh_transfer_command, stdout=subprocess.PIPE, shell=True)
		ssh_transfer_process.wait() #This wait ensures that the process finishes before we try to communicate. Else we break the pipe.
		ssh_transfer_output, ssh_transfer_error = ssh_transfer_process.communicate()

		ssh_setup_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'chmod +x honeypot_install.sh && sudo ./honeypot_install.sh'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		ssh_setup_process = subprocess.Popen(ssh_setup_command, stdout=subprocess.PIPE, shell=True)
		ssh_setup_process.wait()
		ssh_setup_output, ssh_setup_error = ssh_setup_process.communicate()

def doTelnet(host)
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
	#TODO: Put each of these if statements into their own function. This will make the telnet setup easier since it can just call the ssh setup after its done.
	if host.service == "[ssh]" and host.processed == False:
		doSSH(host)

	if host.service == "[telnet]" and host.processed == False:
		doTelnet(host)