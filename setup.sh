#!/usr/bin/env bash

#First I need to nmap to get the hosts.gnmap file.
nmap -oA hosts 192.168.1.0/24

#Now feed the users and passwords to brutespray.
#Somehow store the host, username, and password together. Maybe this needs python?

#Now loop through the addresses and their respective protocol (telnet or ssh).
	#Connect to each host and then transfer the honeypot setup script with ssh: cat logins.txt | ssh root@192.168.1.166 "cat > logins.txt"
	#However you will need to enter the password for the username. This will probably be done with sshpass: sshpass -p "YOUR_PASSWORD" ssh -o StrictHostKeyChecking=no YOUR_USERNAME@SOME_SITE.COM
	#Run the honeypot setup script on the remote system. This is also probably where the password should be changed and then updated in the list.