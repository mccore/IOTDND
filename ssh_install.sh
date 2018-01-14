#!/bin/sh
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
tar xpf dropbear-2017.75.tar.bz2
cd dropbear-2017.75/
./configure
make install
