#!/bin/sh
sudo apt-get update
sudo apt-get install virtualenv libmpfr-dev libssl-dev libmpc-dev libffi-dev build-essential libpython-dev
sudo adduser --disabled-password cowrie && sudo su - cowrie
wget --no-check-certificate --content-disposition http://github.com/micheloosterhof/cowrie/archive/master.zip
unzip cowrie-master.zip && rm cowrie-master.zip && mv cowrie-master/ cowrie/
cd cowrie && cp cowrie.cfg.dist cowrie.cfg
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade setuptools
pip install --upgrade pip
pip install --upgrade -r requirements.txt
sudo iptables -t nat -A PREROUTING -p tcp --dport 1022 -j REDIRECT --to-port 22
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
#Need to change the honeypot config to allow the root login in the data/userdb.txt file (This will be solved by using fork of honeypot with my modifications)
#Need to change the honeypot config to allow ssh_exec. This also needs testing as I need to limit the exec to honeypots only. Also, can the honeypots use ssh at all?
#I also probably need to change the default honeypot config in order to configure the reporting mechanism. Maybe. Its possible that the json files are the best I can do. Maybe the SQL server can be set up else and added to by the honeypots
#Create a cron job to startup the report.py file if the honeypot has no auto-report mechanism
#This whole thing needs to be tested. It also assumes that apt-get can be used which is debian based. Also it assumes that wget is installed. If it isn't I will need to use busy box I think