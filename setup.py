#!/usr/bin/env python2.7
import subprocess, re, telnetlib, datetime, sys, os.path, random, string

#Create a class to hold host information. I considered using a dictionary but it's easier to edit class variables
#I'm probably going to have to change it so that each IP can have a list of services. As there is no way to know which order the services/IPs are in the list.
#This means that it is possible that if an IP has both Telnet and SSH that Telnet can be found first and SSH will attempt to be installed when none of that should happen. SSH should be used.
#Also I will probably have to make a Service class so that I can have a list of Services in each Host object since each service has its own user and pass.
class Host:
	def __init__(self, IP, service, user, passwd):
		self.processed = False
		self.IP = IP
		self.service = service
		self.user = user
		self.passwd = passwd

def doSSH(host, newuser, newpass):
	#TODO: Error checking

	host.processed = True

	print "{IP}: Checking available disk space".format(IP=host.IP) #
	disk_space_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'df -B1 --output=avail / | sed '1d''".format(passwd=host.passwd, user=host.user, IP=host.IP)
	disk_space_process = subprocess.Popen(disk_space_command, stdout=subprocess.PIPE, shell=True)
	disk_space_process.wait()
	disk_space_output, disk_space_error = disk_space_process.communicate()
	disk_space_output = disk_space_output.strip()
	#print "{IP}: Available space = {space}".format(IP=host.IP, space=disk_space_output)

	date=datetime.datetime.now().strftime("%Y-%m-%d")
	if os.path.isfile("./logins_{date}.txt.enc".format(date=date)):
		#dec_file_command = "openssl aes-256-cbc -d -a -in ./logins_{date}.txt.enc -out ./logins_{date}.txt -k pass:{newpass}".format(date=date, newpass=newpass)
		dec_file_command = "openssl enc -a -d -aes-256-cbc -in ./logins_{date}.txt.enc -out ./logins_{date}.txt -k pass:{newpass}".format(date=date, newpass=newpass)
		dec_file_process = subprocess.Popen(dec_file_command, shell=True)
		#dec_file_process.wait()
		dec_file_output, dec_file_error = dec_file_process.communicate()

	file = open('./logins_{date}.txt'.format(date=date), 'a+')
	file.write("{IP}={user}:{passwd}".format(IP=host.IP, user=newuser, passwd=newpass))
	file.close()

	#enc_file_command = "openssl aes-256-cbc -a -salt -in ./logins_{date}.txt -out ./logins_{date}.txt.enc -k pass:test && rm ./logins_{date}.txt".format(date=date)
	enc_file_command = "openssl enc -aes-256-cbc -a -salt -in ./logins_{date}.txt -out ./logins_{date}.txt.enc -k pass:{newpass} && rm ./logins_{date}.txt".format(date=date, newpass=newpass)
	enc_file_process = subprocess.Popen(enc_file_command, shell=True)
	#enc_file_process.wait()
	enc_file_output, enc_file_error = enc_file_process.communicate()


	print "{IP}: Creating encrypted password for {newuser}".format(IP=host.IP, newuser=newuser)
	#pass_command = "openssl passwd -crypt test"
	pass_command = "mkpasswd -m sha-512 {newpass}".format(newpass=newpass)
	pass_process = subprocess.Popen(pass_command, stdout=subprocess.PIPE, shell=True)
	pass_process.wait()
	pass_output, pass_error = pass_process.communicate()
	passhash = re.sub(r"\$", "\\$", pass_output).rstrip()

	print "{IP}: Adding new user {newuser}".format(IP=host.IP, newuser=newuser)
	#newuser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo adduser --gecos "" --disabled-password {anewuser} && echo {anewuser}:{anewuserpassword} | sudo chpasswd'".format(passwd=host.passwd, user=host.user, IP=host.IP, anewuser=newuser, anewuserpassword=newpass)
	newuser_command = '''sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} "sudo useradd -m -s /bin/bash -g sudo -p '{encpass}' {newuser}"'''.format(passwd=host.passwd, user=host.user, IP=host.IP, encpass=passhash, newuser=newuser)
	newuser_process = subprocess.Popen(newuser_command, stdout=subprocess.PIPE, shell=True)
	newuser_process.wait()
	newuser_output, newuser_error = newuser_process.communicate()

	print "{IP}: Sudoing new user {newuser}".format(IP=host.IP, newuser=newuser)
	sudo_user_command = '''sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'sudo echo "{newuser} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' '''.format(passwd=host.passwd, user=host.user, IP=host.IP, newuser=newuser)
	sudo_user_process = subprocess.Popen(sudo_user_command, stdout=subprocess.PIPE, shell=True)
	sudo_user_process.wait()
	sudo_user_output, sudo_user_error = sudo_user_process.communicate()

	install_size=235929600
	if int(disk_space_output) > install_size: #Check to make sure the available diskspace is greater than 225Mb to make sure the full honeypot install will fit.
		print "{IP}: Transferring honeypot install script".format(IP=host.IP)
		transfer_install_command = "cat honeypot_install.sh | sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'cat > honeypot_install.sh'".format(passwd=host.passwd, user=host.user, IP=host.IP)
		transfer_install_process = subprocess.Popen(transfer_install_command, stdout=subprocess.PIPE, shell=True)
		transfer_install_process.wait() #This wait ensures that the process finishes before we try to communicate. Else we break the pipe.
		transfer_install_output, transfer_install_error = transfer_install_process.communicate()

		print "{IP}: Running install script".format(IP=host.IP)
		setup_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} 'chmod +x honeypot_install.sh && ./honeypot_install.sh {newuser}'".format(passwd=host.passwd, user=host.user, IP=host.IP, newuser=newuser)
		setup_process = subprocess.Popen(setup_command, stdout=subprocess.PIPE, shell=True)
		setup_process.wait()
		setup_output, setup_error = setup_process.communicate()

		get_local_ip_command = "ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'" #This is done to get the local IP of the device so that it can be used to send the JSONs too.
		get_local_ip_process = subprocess.Popen(get_local_ip_command, stdout=subprocess.PIPE, shell=True)
		get_local_ip_process.wait()
		get_local_ip_output, get_local_ip_error = get_local_ip_process.communicate()
		get_local_ip_output = get_local_ip_output.rstrip()

		print "{IP}: Adding cron job to send JSON to report server at {server}".format(IP=host.IP, server=get_local_ip_output)
		report_command = '''sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 '(crontab -u {newuser} -l ; echo "00 06 * * * nc -w 3 {server} 3333 < /home/cowrie/cowrie/log/cowrie.json") | crontab -u {newuser} -' '''.format(passwd=host.passwd, user=host.user, IP=host.IP, server=get_local_ip_output, newuser=newuser) #List the current cron jobs, create a new one to report the json at 6AM every day, and pipe all that into crontab.
		report_process = subprocess.Popen(report_command, stdout=subprocess.PIPE, shell=True)
		report_process.wait() #This wait ensures that the process finishes before we try to communicate. Else we break the pipe.
		report_output, report_error = report_process.communicate()
	else:
		print "{IP}: Not enough space to install honeypot".format(IP=host.IP)

	print "{IP}: Disabling old user {olduser}".format(IP=host.IP, olduser=host.user)
	deluser_command = "sshpass -p {passwd} ssh -o StrictHostKeyChecking=no {user}@{IP} -p 1022 'sudo passwd -l {user}'".format(passwd=host.passwd, user=host.user, IP=host.IP)
	deluser_process = subprocess.Popen(deluser_command, stdout=subprocess.PIPE, shell=True)
	deluser_process.wait()
	deluser_output, deluser_error = deluser_process.communicate()

def doTelnet(host, newuser, newpass):
	#First thing I'm going to do is transfer an ssh setup file via netcat. Then I'm going to run it via telnet. Only after that will telnet be blocked.
	#TODO: Error checking?
	#TODO: Space checking for ssh install
	#TODO: If there is not enough space to install SSH, it should create a new user and lock the old one like doSSH does.
	#TODO: A possible solution to having to rewrite the whole Host class is to simply check here if port 22 is open. (Working)
	#TODO: Try to use read_all() for Telnet. Basically, for the disk space, login and run df then exit and read all

	print "{IP}: Checking remote host for SSH".format(IP=host.IP)
	ssh_check_command = "nc -z {IP} 22".format(IP=host.IP)
	ssh_check_process = subprocess.Popen(ssh_check_command, stdout=subprocess.PIPE, shell=True)
	ssh_check_process.wait()
	ssh_check_output, ssh_check_error = ssh_check_process.communicate()
	ssh_check_rc = ssh_check_process.returncode

	# if ssh_check_rc == 0:
	# 	print "{IP:} SSH is available. Skipping Telnet.".format(IP=host.IP)
	# 	return None

	host.processed = True

	tn1 = telnetlib.Telnet(host.IP)

	print "{IP}: Logging in".format(IP=host.IP)
	tn1.read_until("login: ")
	tn1.write(host.user + "\r\n")
	tn1.read_until("Password: ")
	tn1.write(host.passwd + "\r\n")

	print "{IP}: Checking available disk space".format(IP=host.IP)
	tn1.write("df -B1 --output=avail /\r\n")
	tn1.write("exit\r\n")
	disk_space_output = tn1.read_all() #Need to play with the eager part.
	disk_space_output = disk_space_output.splitlines()
	actual_disk_space = ""
	disk_space_iter = iter(disk_space_output)
	for line in disk_space_iter:
		if line.strip() == "Avail":
			actual_disk_space = next(disk_space_iter).strip()
			print actual_disk_space
			break
	#disk_space_regex = re.search("^[0-9]+$", disk_space_output) #df -B1 --output=avail / | sed '1d'((.*\r\n){2})
	print "Telnet disk space {space}".format(space=disk_space_output[-3])

	tn = telnetlib.Telnet(host.IP)

	print "{IP}: Relogging in".format(IP=host.IP)
	tn.read_until("login: ")
	tn.write(host.user + "\r\n")
	tn.read_until("Password: ")
	tn.write(host.passwd + "\r\n")

	install_size=136314880
	if int(disk_space_output) > install_size:
		print "{IP}: Listening for ssh install script".format(IP=host.IP)
		tn.write("nc -l -p 1234 > ssh_install.sh &\r\n")

		print "{IP}: Transferring ssh install script".format(IP=host.IP)
		transfer_install_command = "sleep 5 && nc -w 10 {IP} 1234 < ssh_install.sh".format(IP=host.IP)
		transfer_install_process = subprocess.Popen(transfer_install_command, stdout=subprocess.PIPE, shell=True)
		#transfer_install_process.wait() #This wait ensures that the process finishes before we try to communicate. Else we break the pipe.
		transfer_install_output, transfer_install_error = transfer_install_process.communicate()

		print "{IP}: Running ssh install script".format(IP=host.IP)
		tn.write("sleep 10\r\n")
		tn.write("chmod +x ssh_install.sh && ./ssh_install.sh &\r\n")
		tn.write("exit\r\n")
		#print tn.read_all() #This prints literally everything that happened on the remote host. I'll leave it disabled because it clutters the terminal
	else:
		print "{IP}: Not enough space to install SSH".format(IP=host.IP)

		date=datetime.datetime.now().strftime("%Y-%m-%d")
		if os.path.isfile("./logins_{date}.txt.enc".format(date=date)):
			#dec_file_command = "openssl aes-256-cbc -d -a -in ./logins_{date}.txt.enc -out ./logins_{date}.txt -k pass:{newpass}".format(date=date, newpass=newpass)
			dec_file_command = "openssl enc -a -d -aes-256-cbc -in ./logins_{date}.txt.enc -out ./logins_{date}.txt -k pass:{newpass}".format(date=date, newpass=newpass)
			dec_file_process = subprocess.Popen(dec_file_command, shell=True)
			#dec_file_process.wait()
			dec_file_output, dec_file_error = dec_file_process.communicate()

		file = open('./logins_{date}.txt'.format(date=date), 'a+')
		file.write("{IP}={user}:{passwd}".format(IP=host.IP, user=newuser, passwd=newpass))
		file.close()

		#enc_file_command = "openssl aes-256-cbc -a -salt -in ./logins_{date}.txt -out ./logins_{date}.txt.enc -k pass:test && rm ./logins_{date}.txt".format(date=date)
		enc_file_command = "openssl enc -aes-256-cbc -a -salt -in ./logins_{date}.txt -out ./logins_{date}.txt.enc -k pass:{newpass} && rm ./logins_{date}.txt".format(date=date, newpass=newpass)
		enc_file_process = subprocess.Popen(enc_file_command, shell=True)
		#enc_file_process.wait()
		enc_file_output, enc_file_error = enc_file_process.communicate()

		print "{IP}: Creating encrypted password for {newuser}".format(IP=host.IP, newuser=newuser)
		#pass_command = "openssl passwd -crypt test"
		pass_command = "mkpasswd -m sha-512 {newpass}".format(newpass=newpass)
		pass_process = subprocess.Popen(pass_command, stdout=subprocess.PIPE, shell=True)
		pass_process.wait()
		pass_output, pass_error = pass_process.communicate()
		passhash = re.sub(r"\$", "\\$", pass_output).rstrip()

		print "{IP}: Adding new user {newuser}".format(IP=host.IP, newuser=newuser)
		tn.write('''sudo useradd -m -s /bin/bash -g sudo -p '{encpass}' {newuser}\r\n'''.format(encpass=passhash, newuser=newuser))

		print "{IP}: Sudoing new user {newuser}".format(IP=host.IP, newuser=newuser)
		tn.write('''sudo echo "{newuser} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers\r\n'''.format())

		print "{IP}: Disabling old user {olduser}".format(IP=host.IP, olduser=host.user)
		tn.write('''sudo passwd -l {user}\r\n'''.format(user=host.user))
		tn.write("exit\r\n")

def main():
	# print command line arguments
	for arg in sys.argv[1:]:
		print arg

	#First I need to nmap to get the hosts.gnmap file.
	#TODO: The IP address range should be an argument. Default behavior should be to use the range of the default gateway
	print "Nmapping network"
	nmap_command = "nmap -oA hosts 192.168.1.0/24"
	nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, shell=True)
	nmap_output, nmap_error = nmap_process.communicate()

	#Now feed the users and passwords to brutespray. This allows us to have all the information needed for setup
	print "Bruteforcing devices"
	brutespray_command = "brutespray --file hosts.gnmap --service ssh,telnet --threads 3 --hosts 5 -U users.txt -P passwords.txt | grep 'ACCOUNT FOUND'"
	brutespray_process = subprocess.Popen(brutespray_command, stdout=subprocess.PIPE, shell=True)
	brutespray_output, brutespray_error = brutespray_process.communicate()

	#The way subprocess works means that all of the chars have to be joined together before the output can be split into lines which is what I actually want to process
	output_as_list = []
	for aChar in brutespray_output:
		output_as_list.append(aChar)
	real_output = ''.join(output_as_list).split('\n')

	#I should make sure there aren't any duplicates in the hosts list. I should allow multiple of the same IPs but only one of each service.
	#Create the host objects for the next for loop
	print "Processing hosts"
	hosts = []
	# Telnet is extremely and notoriously difficult to bruteforce just because of how it works. For this reason I have added a guarenteed working Telnet example.
	hosts.append(Host("192.168.1.76", "[telnet]", "root", "dietpi"))
	for line in real_output:
		if line:
			anIP = line.split()[4]
			aService = line.split()[2]
			aUser = line.split()[6]
			aPass = line.split()[8]
			if aPass == "(none)": #If the pass is (none) then it should be blank
				aPass = ""
			aHost = Host(anIP, aService, aUser, aPass)
			print "Destination: {IP}, Service: {service}, User: {user}, Password: {password}".format(IP=anIP, service=aService, user=aUser, password=aPass)
			hosts.append(aHost)

	#Now loop through the addresses and their respective protocol (telnet or ssh).
	print "Looping through hosts"
	for host in hosts:
		#Run the honeypot setup script on the remote system.
		#TODO: Need to make sure that if a host has the ability to use ssh then it is. Basically, telnet should be a last resort. A way to achieve this might be to sort the hosts list by service so that ssh is on top.
		#TODO: Somehow doSSH needs to take in a new user and password. Perhaps this whole file should have arguments for one master user and password combo, procedural generation, or manual input
		passlength=10
		randpass = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(passlength))
		if host.service == "[ssh]" and host.processed == False:
			#doSSH(host, "test", "test")
			continue

		if host.service == "[telnet]" and host.processed == False:
			doTelnet(host, "test", "test")
			#doSSH(host, "test", "test")
			continue

	print "Creating local cron command and starting server"
	cron_command = '''(crontab -l ; echo "@reboot ~/IOTDND/report_server.sh {logpath}") | crontab - ; chmod +x ~/IOTDND/report_server.sh && ~/IOTDND/report_server.sh {logpath} &'''.format(logpath="~/IOTDND")
	cron_process = subprocess.Popen(cron_command, shell=True)
	#cron_process.wait()
	cron_output, cron_error = cron_process.communicate()

if __name__ == "__main__":
    main()