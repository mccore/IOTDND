#!/bin/sh
sudo apt-get install build-essential zlib1g-dev
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
tar xpf dropbear-2017.75.tar.bz2
cd dropbear-2017.75/
./configure
make install
chmod 700 /etc/dropbear
RSA_KEYFILE=/etc/dropbear/dropbear_rsa_host_key
DSS_KEYFILE=/etc/dropbear/dropbear_dss_host_key
dropbearkey -t dss -f $DSS_KEYFILE
dropbearkey -t rsa -f $RSA_KEYFILE
sudo /etc/init.d/dropbear start
(crontab -l ; echo "@reboot sudo /etc/init.d/dropbear start") | crontab -
#The actual server needs to be tested but it should be working