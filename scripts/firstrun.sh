#!/bin/sh  

### backup the sysctl
sysctl -a > /root/firstrun-sysctl.conf.bak

### wget https://example.com/firstrun.sh -O – | sh – 

### remove existing SSH Server Key files (installed from ISO)
rm /etc/ssh/ssh_host_*

### create new SSH Server Key files
dpkg-reconfigure openssh-server

### restart SSH Server
systemctl restart openssh-server

### sync NTP: https://askubuntu.com/questions/254826/how-to-force-a-clock-update-using-ntp/254846#254846
( /etc/init.d/ntp stop
until ping -nq -c3 8.8.8.8; do
   echo "Waiting for network..."
done
ntpdate -s time.nist.gov
/etc/init.d/ntp start )&

### fetch current package index
apt-get update

### install `locate` and run `updatedb` to index system
### install `netselect-apt` for closest download mirror
apt-get install iptables-optimizer iptables-persistent locate

### enable iptables load at boot
systemctl enable netfilter-persistent
systemctl start netfilter-persistent

### enable unbound load at boot
# systemctl enable unbound
# systemctl start unbound

touch /etc/unbound/unbound_ad_servers
# wget https://pgl.yoyo.org/adservers/serverlist.php?hostformat=unbound&showintro=0&mimetype=plaintext -O /etc/unbound/unbound_ad_servers

   #cat <<EOF > /etc/resolv.conf
   ## Generated by resolvconf
   #nameserver ::1
   #nameserver 127.0.0.1
   #EOF

### setup the resolv.conf file for local DNS (Unbound)
### backup DNS is set to PIA resolver1 and resolver2
resolvCONF=/etc/resolv.conf
chattr -i $resolvCONF
echo "# Generated by resolvconf" > $resolvCONF
echo "nameserver 127.0.0.1" >> $resolvCONF
echo "nameserver ::1" >> $resolvCONF
echo "nameserver 209.222.18.222" >> $resolvCONF
echo "nameserver 209.222.18.218" >> $resolvCONF
chattr +i $resolvCONF

### update closest mirror to download from
# netselect-apt

### let's add a cron job (00:00 every day/month/day of week) in case of environment migration for new download mirror: 
### https://stackoverflow.com/questions/878600/how-to-create-a-cron-job-using-bash-automatically-without-the-interactive-editor#comment75562934_878647
# (crontab -l 2>/dev/null ; echo "00 00 * * * sudo netselect-apt") | sort | uniq | crontab -

### grab the root.hints file for unbound
### we make two requests because timestamping isn't compatible with output, we use `touch` to update the filesystem timestamp
# wget https://www.internic.net/domain/named.cache -O /etc/unbound/root.hints && roothintsTIMESTAMP=`wget -S https://www.internic.net/domain/named.cache` && touch -a -m -t $roothintsTIMESTAMP /etc/unbound/root.hints

### update `hostapd` default file to utilize the `hostapd.conf` file
# sed -i -- 's/#DAEMON_CONF=""/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/g' /etc/default/hostapd

### index system for use with `locate`
updatedb
