#!/bin/sh
newuser=$1
#sudo apt-get -y update
#sudo apt-get -y install virtualenv libmpfr-dev libssl-dev libmpc-dev libffi-dev build-essential libpython-dev
sudo apt-get -y install python-virtualenv libssl-dev libffi-dev build-essential libpython-dev python2.7-minimal
#sudo apt-get -y install python-virtualenv libmpfr-dev libmpc-dev libssl-dev libffi-dev build-essential libpython-dev python2.7-minimal
sudo adduser --gecos "" --disabled-password cowrie && sudo su - cowrie << EOF
wget --no-check-certificate --content-disposition http://github.com/mccore/cowrie/archive/master.zip
unzip cowrie-master.zip && rm cowrie-master.zip && mv cowrie-master/ cowrie/
cd cowrie && cp cowrie.cfg.dist cowrie.cfg
virtualenv --python=python2.7 cowrie-env
source cowrie-env/bin/activate
pip install --upgrade setuptools
pip install --upgrade pip
pip install --upgrade -r requirements.txt
~/cowrie/bin/cowrie start
EOF
sudo iptables -t nat -A PREROUTING -p tcp --dport 1022 -j REDIRECT --to-port 22
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -A INPUT -p tcp -m tcp --dport 23 -j DROP
(crontab -u $newuser -l ; echo "@reboot sudo iptables -t nat -A PREROUTING -p tcp --dport 1022 -j REDIRECT --to-port 22 ; sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 ; sudo iptables -A INPUT -p tcp -m tcp --dport 23 -j DROP") | crontab -u $newuser -
(crontab -u $newuser -l ; echo "@reboot su - cowrie -c '~/cowrie/bin/cowrie start'") | crontab -u $newuser -

#Need to change the honeypot config to allow the root login in the data/userdb.txt file (This will be solved by using fork of honeypot with my modifications)
#Need to change the honeypot config to allow ssh_exec. This also needs testing as I need to limit the exec to honeypots only. Also, can the honeypots use ssh at all?
#I am going to need to also block telnet which should be added to the iptables crontab line
#This whole thing needs to be tested. It also assumes that apt-get can be used which is debian based. Also it assumes that wget is installed. If it isn't I will need to use busybox I think. Testing on dietpi successful
#I need to add if statements to check for the commands that I use. If it doesn't have them then I install busybox.
#I need to check the package manager and use yum if its redhat. That also means this needs to be tested on redhat
