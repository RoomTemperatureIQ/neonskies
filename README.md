# neonskies

# .bashrc
export LANG="en_US.UTF-8"  
export PROMPT_COMMAND='history -a'  
export HISTSIZE=1000000  
export HISTFILESIZE=1000000  
export HISTCONTROL=ignoredups:ignorespace   
shopt -s cmdhist  
shopt -s histappend  

# /etc/fstab
```
# <file system> <mount point>   <type>  <options>       <dump>  <pass>  
proc /proc proc nodev,noexec,nosuid 0  0  
/dev/mmcblk0p2  / ext4 noatime,errors=remount-ro 0 1  
# Change this if you add a swap partition or file  
# dev/SWAP none swap sw 0 0  
/dev/mmcblk0p1 /boot vfat noauto 0 0  
```

# /etc/ntopng.conf
`-e=`  
`-i=eth0`  
`-i=wlan0`  
`-i=wlan1`  
`-w=3000`  

# /etc/resolv.conf
`chattr +i /etc/resolv.conf` # make read-only (immutable)

# /etc/sudoers
`root	ALL=(ALL:ALL) ALL`  
`pi	ALL=(ALL:ALL) ALL`  

# /etc/hostapd/hostapd.conf

# /etc/network/interfaces

# /etc/sysctl.conf
net.ipv4.ip_forward=1  
`sysctl -w net.ipv4.ip_forward=1`  

# movein.sh
`passwd`  
setup non-priv user that can `sudo`  
`/etc/ssh/sshd_config PermitRootLogin false`  
`rm /etc/ssh/ssh_host_*`  
`dpkg-reconfigure openssh-server`  
`systemctl restart openssh-server`  
`dpkg-reconfigure tzdata`  
`update-locale`  
`gparted`  
`resize2fs`  
`apt-get update`  
`apt-get install bleachbit curl htop iptables-optimizer locate lynx macchanger nethogs speedtest-cli systemd-gui ntopng openvpn unbound dnscrypt isc-dhcp-server hostapd wpa_supplicant wireless-tools iw wvdial`  
`apt-get dist-upgrade`  
`apt-get autoremove`  
`apt-get autoclean`  
`updatedb`  
shell settings (bash_history / etc.)  

run I/O benchmarking (dd_obs_test / dd_ibs_test)  
`fdisk -l`  
`sudo umount /dev/sdX`  
`sudo dd if=/path/to/OperatingSystem.iso of=/dev/sdX bs=4M && sync`   
setup swap file  
run `bootgui.sh disable`  

# setup core services
setup deb packages (sources.list)  
setup fastest deb mirror (`netselect-apt`)  
setup `unattended-upgrades`  

setup `iptables` on rpi  
setup `iptables-optimizer` in crontab hourly  
setup `iptables-save` in crontab  
setup `iptables-restore` on boot  
setup cron daily restart(?)  

setup `easytether` on rpi  
setup `openvpn` on rpi  
setup `unbound` (DNS caching server) on rpi (use VPN DNS as authoritative)  
setup DNSSEC (`dnscrypt`) on rpi  
setup `isc-dhcp-server` on rpi  
setup `hostapd` on rpi  
setup `wpa_supplicant` on rpi  
setup `ntopng` on rpi  

# pia-nm.sh
`apt-get install uuid-runtime`  
look into gnome-keyring  
password-flags  
`nmcli con up id 'VPN_Name'`  
`nmcli con down id 'VPN_Name'`  

# wireshark (tshark)
`sudo chgrp wireshark /usr/bin/dumpcap`  
`sudo chmod o-rx /usr/bin/dumpcap`  
`sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap`  
`sudo usermod -a -G wireshark $USER`  
`xhost +si:localuser:wireshark >/dev/null`  
.xauthority  
`sudo wireshark`  
`sudo tshark`  

# Node.js (NPM)
ethereumjs-tx  

# FreeNode - SASL & Cloak
Server: chat.freenode.net  
Desc: FreeNode  
Port: 6697 # Port for SASL  
Pass:  
SSL: [✔]  
SASL: [✔]  
Auto: [ ]  
Boot: [ ]  
Nick:  
User: null  
Name: null  
SASL Login:  
SASL PW:  
Join Channels: (srv), #freenode  

Client behavior:  
Hide Device Info: [✔]  

Logging:  
Log: [✔]  
Timestamp Logs: [✔]  

`/nick $nick`  
`/msg nickserv set accountname $nick`  
`/msg nickserv register $password $email`  
`/nick $nick`  
`/msg nickserv group`  
`/msg nickserv set hidemail on`  
`/msg nickserv set emailmemos on`  
`/msg nickserv set enforce on`  
`/msg nickserv set private on`  
`/msg nickserv set quietchg on`  
`/msg nickserv set property url $url`  
`/msg nickserv set property icq $icq`  
`/msg nickserv set property sign $language`  

`/msg memoserv help`  
`/msg nickserv help`  
`/ping $nick`  
`/stats p #Staff`  
`/version $nick`  
`/whois $nick`  
`/ctcp $nick ping`  
`/ctcp $nick userinfo`  
`/ctcp $nick version`  
`/ctcp $nick xdcc`  
mode: +Z+i  

# extra
setup kernel build environment  
recompile kernel  
setup geth light node sync  
osquery.io `osqueryd`  

# OpenVPN
 block-outside-dns  

# ProxyChains

# SNORT

# SQUID

# VirtualGL / TurboVNC

# gkeyring.py

# youtube-dl.py

# pfSense

