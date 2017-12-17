#!/usr/bin/env python2.7
import subprocess, re

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

hosts = []
for line in brutespray_output:
	hosts.append(Host(line.split()[4], line.split()[2], line.split()[6], line.split()[8]))

print hosts

#Now loop through the addresses and their respective protocol (telnet or ssh).
	#Connect to each host and then transfer the honeypot setup script with ssh: cat logins.txt | ssh root@192.168.1.166 "cat > logins.txt"
	#However you will need to enter the password for the username. This will probably be done with sshpass: sshpass -p "YOUR_PASSWORD" ssh -o StrictHostKeyChecking=no YOUR_USERNAME@SOME_SITE.COM
	#Run the honeypot setup script on the remote system. This is also probably where the password should be changed and then updated in the list.


#Create a class to hold host information. I considered using a dictionary but it's easier to edit class variables
class Host:
	def __init__(self, IP, service, user, passwd):
		self.IP = IP
		self.service = service
		self.user = user
		self.passwd = passwd