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
nmap_command = "nmap -oA hosts 192.168.1.0/24"
nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, shell=True)
nmap_output, nmap_error = nmap_process.communicate()

#Now feed the users and passwords to brutespray.
#Somehow store the service, host, username, and password together.
#Python can be used in this script because it is on the setup device which should have no trouble with python.
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

#Now loop through the addresses and their respective protocol (telnet or ssh).
for host in hosts:
	#Connect to each host and then transfer the honeypot setup script with ssh: cat logins.txt | ssh root@192.168.1.166 "cat > logins.txt"
	#However you will need to enter the password for the username. This will probably be done with sshpass: sshpass -p "YOUR_PASSWORD" ssh -o StrictHostKeyChecking=no YOUR_USERNAME@SOME_SITE.COM
	#Run the honeypot setup script on the remote system. This is also probably where the password should be changed and then updated in the list.
	#Need to make sure that if a host has the ability to use ssh then it is. Basically, telnet should be a last resort
	if host.service == "[ssh]" and host.processed == False:
		#I need to create a new password here as well.
		host.processed = True
		with open("honeypot_install.sh", "r") as script:
			data = script.read()
		ssh_transfer_command = "cat honeypot_install.sh | sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'cat > honeypot_install.sh'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		#print "{passwd} {user}@{IP} sending {file}".format(passwd=host.passwd, user=host.user, IP=host.IP, file=data)
		#ssh_transfer_command = 'sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} "echo {file} > honeypot_install.sh"'.format(passwd=host.passwd, user=host.user, IP=host.IP, file=data)
		ssh_transfer_process = subprocess.Popen(ssh_transfer_command, stdout=subprocess.PIPE, shell=True)
		ssh_transfer_process.wait()
		ssh_transfer_output, ssh_transfer_error = ssh_transfer_process.communicate()


	if host.service == "[telnet]" and host.processed == False:
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