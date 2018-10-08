#!/bin/sh  

rm /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
dpkg-reconfigure ssh
systemctl restart openssh-server
systemctl restart ssh

apt-get update
apt-get install locate netselect-apt
netselect-apt
updatedb
