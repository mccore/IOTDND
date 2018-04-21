#!/bin/sh
newuser=$1
if [ -x "$(command -v apt-get)" ]; then
	sudo apt-get -y install python-virtualenv libssl-dev libffi-dev build-essential libpython-dev python2.7-minimal
fi
if [ -x "$(command -v yum)" ]; then
	sudo yum install -y python-virtualenv openssl-devel libffi-devel make automake gcc gcc-c++ kernel-devel libpython-devel python27 python2-virtualenv
fi
#sudo adduser --gecos "" --disabled-password cowrie && sudo su - cowrie << EOF
sudo useradd -m -s /bin/bash cowrie && sudo su - cowrie << EOF
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
if [ -x "$(command -v apt-get)" ]; then
	sudo apt-get -y update
fi
if [ -x "$(command -v yum)" ]; then
	sudo yum update -y
fi

#I need to add if statements to check for the commands that I use. If it doesn't have them then I install busybox.
#Test on Fedora