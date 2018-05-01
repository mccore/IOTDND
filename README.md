# IoT Honeypots As Distributed Network Defenses:
## Introduction:
Although IoT devices are becoming more widespread and popular, the security that protects them lags behind. Many devices are never patched or changed from their default configurations. The primary threat to these devices are automated attacks like botnets which typically attack either the default configurations or known vulnerabilities of the device. This project attempts to address these issues. The default configuration is changed so that the default user is disabled and a new user with a strong password is installed in its place. This helps protect against attacks similar to the Mirai botnet. In addition, the device is updated in order to patch any security vulnerabilities which are the primary attack surface of the IoT Reaper botnet. This project also goes one step further and installs a honeypot if there is space on the device in order to monitor for possible attacks and log information about the attackers. Each honeypot is allowed to make fake connections to other devices. This means that it is possible to study how an attack spreads from one device to another without the attack actually being carried out.

## Assumptions:
Each IoT device must meet the following specifications:
* No RTOSs. The project needs buffers and storage in order to function and a Real Time Operating System does not provide that functionality.
* Needs to have a shell. Preferably bash.
* Needs to enough space to install python for the honeypot. This is strongly suggested but not necessary. The program has fall backs if there is not enough space for python and the honeypot.
* Needs to have either a Telnet or SSH server. If it only has Telnet the program will attempt to install SSH if space constraints permit.
* Needs to use Debian/Red Hat/OpenBSD.
* Needs to have the following commands: `iptables`, `df`, `cat`, `crontab`, `nc`, `useradd`, `adduser`, `wget`, `unzip`, `tar`, and a package manager.

## Dependencies:
These are for device running the setup:
* sshpass
* openssl >= 1.1.0e
* mkpasswd
* Python 2.7
* Nmap
* Brutespray
* concurrent.futures
* crontab

## Confirmed Operating Systems:
* Any Debian variant
* Redhat/Fedora

## Usage:
See `python setup.py -h` for usage instructions. Note that flags without square brackets are mandatory.

## In Action:
https://youtu.be/9GnaeJuld0s