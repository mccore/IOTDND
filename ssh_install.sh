#!/bin/sh
echo "Starting install" >> ssh_install.log
sudo apt-get install build-essential zlib1g-dev
echo "apt-get build essential and zlib done" >> ssh_install.log
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
echo "wget done" >> ssh_install.log
tar xpf dropbear-2017.75.tar.bz2
echo "tar done" >> ssh_install.log
cd dropbear-*/
echo "cd done" >> ssh_install.log
./configure
echo "configure done" >> ssh_install.log
make install
echo "make install done" >> ssh_install.log
chmod 700 /etc/dropbear
echo "chmod done" >> ssh_install.log
RSA_KEYFILE=/etc/dropbear/dropbear_rsa_host_key
DSS_KEYFILE=/etc/dropbear/dropbear_dss_host_key
dropbearkey -t dss -f $DSS_KEYFILE
echo "dropbear dss done" >> ssh_install.log
dropbearkey -t rsa -f $RSA_KEYFILE
echo "dropbear rsa done" >> ssh_install.log
sudo /etc/init.d/dropbear start
echo "dropbear start done" >> ssh_install.log
(crontab -l ; echo "@reboot sudo /etc/init.d/dropbear start") | crontab -
echo "cron done and about to exit" >> ssh_install.log
exit
#The actual server needs to be tested but it should be working