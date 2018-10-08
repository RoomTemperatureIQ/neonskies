#!/bin/sh  

rm /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
systemctl restart openssh-server

# sync NTP: https://askubuntu.com/questions/254826/how-to-force-a-clock-update-using-ntp/254846#254846
( /etc/init.d/ntp stop
until ping -nq -c3 8.8.8.8; do
   echo "Waiting for network..."
done
ntpdate -s time.nist.gov
/etc/init.d/ntp start )&

apt-get update
apt-get install locate netselect-apt
netselect-apt
updatedb
