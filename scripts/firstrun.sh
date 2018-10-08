#!/bin/sh  

# remove existing SSH Server Key files (installed from ISO)
rm /etc/ssh/ssh_host_*

# create new SSH Server Key files
dpkg-reconfigure openssh-server

# restart SSH Server
systemctl restart openssh-server

# sync NTP: https://askubuntu.com/questions/254826/how-to-force-a-clock-update-using-ntp/254846#254846
( /etc/init.d/ntp stop
until ping -nq -c3 8.8.8.8; do
   echo "Waiting for network..."
done
ntpdate -s time.nist.gov
/etc/init.d/ntp start )&

# fetch current package index
apt-get update

# install `locate` and run `updatedb` to index system
# install `netselect-apt` for closest download mirror
apt-get install locate netselect-apt

# update download to closest mirror
netselect-apt

# index system for use with `locate`
updatedb
