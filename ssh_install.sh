#!/bin/sh
wget https://mojzis.com/software/tinyssh/tinyssh-20180110.tar.gz
wget https://mojzis.com/software/tinyssh/tinyssh-20180110.tar.gz.asc
gpg --verify tinyssh-20180110.tar.gz.asc tinyssh-20180110.tar.gz
gunzip < tinyssh-20180110.tar.gz | tar -xf -
cd tinyssh-20180110
make
sudo make install
sudo tinysshd-makekey /etc/tinyssh/sshkeydir
sudo echo "ssh stream tcp nowait root /usr/sbin/tinysshd tinysshd -l -v /etc/tinyssh/sshkeydir" >> /etc/inetd.conf
sudo /etc/init.d/xinetd restart