#!/bin/sh
if [ -x "$(command -v apt-get)" ]; then
	sudo apt-get install -y build-essential zlib1g-dev
	wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
	tar xpf dropbear-2017.75.tar.bz2
	~/dropbear-2017.75/configure
	make -C ~/dropbear-2017.75/ install
	chmod 700 /etc/dropbear
	RSA_KEYFILE=/etc/dropbear/dropbear_rsa_host_key
	DSS_KEYFILE=/etc/dropbear/dropbear_dss_host_key
	dropbearkey -t dss -f $DSS_KEYFILE
	dropbearkey -t rsa -f $RSA_KEYFILE
	sudo /etc/init.d/dropbear start
	(crontab -l ; echo "@reboot sudo /etc/init.d/dropbear start") | crontab -
	sudo apt-get -y update
fi
if [ -x "$(command -v yum)" ]; then
	sudo yum install -y dropbear
	RSA_KEYFILE=/etc/dropbear/dropbear_rsa_host_key
	DSS_KEYFILE=/etc/dropbear/dropbear_dss_host_key
	dropbearkey -t dss -f $DSS_KEYFILE
	dropbearkey -t rsa -f $RSA_KEYFILE
	dropbear
	(crontab -l ; echo "*/1 * * * * sudo dropbear") | crontab -
	sudo yum update -y
fi

#For redhat/fedora we don't need to download and build from source since both OSes have Dropbear in their repositories