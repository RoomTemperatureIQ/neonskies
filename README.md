# neonskies

# .bashrc
export LANG="en_US.UTF-8"  
export PROMPT_COMMAND='history -a'  
export HISTSIZE=1000000  
export HISTFILESIZE=1000000  
export HISTCONTROL=ignoredups:ignorespace   
shopt -s cmdhist  
shopt -s histappend  

# /etc/hostapd/hostapd.conf

# /etc/network/interfaces

# /etc/sysctl.conf
net.ipv4.ip_forward=1  
`sysctl -w net.ipv4.ip_forward=1`

# movein.sh
`rm /etc/ssh/ssh_host_*`  
`dpkg-reconfigure openssh-server`  
`systemctl restart openssh-server`  
`passwd`  
`dpkg-reconfigure tzdata`  
`/etc/ssh/sshd_config PermitRootLogin false`  
`gparted`  
`resize2fs`  
`apt-get update`  
`apt-get install bleachbit curl htop locate lynx macchanger nethogs speedtest-cli systemd-gui ntopng openvpn unbound dnscrypt isc-dhcp-server hostapd wpa_supplicant wireless-tools iw wvdial`  
`apt-get dist-upgrade`  
`apt-get autoremove`  
`apt-get autoclean`  
`updatedb`  
setup non-priv user\
shell settings (bash_history / etc.)

run I/O benchmarking (dd_obs_test / dd_ibs_test)\
`fdisk -l`  
`sudo umount /dev/sdX`  
`sudo dd if=/path/to/OperatingSystem.iso of=/dev/sdX bs=4M && sync`  
setup swap file\
run `bootgui.sh disable`

# setup core services
setup deb packages (sources.list)\
setup fastest deb mirror (`netselect-apt`)\
setup `unattended-upgrades`

setup iptables on rpi\
setup iptables-save in crontab\
setup iptables-restore on boot\
setup cron daily restart(?)

setup `easytether` on rpi\
setup `openvpn` on rpi\
setup `unbound` (DNS caching server) on rpi (use VPN DNS as authoritative)\
setup DNSSEC (`dnscrypt`) on rpi\
setup `isc-dhcp-server` on rpi\
setup `hostapd` on rpi\
setup `wpa_supplicant` on rpi\
setup `ntopng` on rpi\

# pia-nm.sh
`apt-get install uuid-runtime`  
look into gnome-keyring\
`nmcli con up VPN_Name`  
`nmcli con down VPN_Name`  

# wireshark (tshark)
`sudo chgrp wireshark /usr/bin/dumpcap`  
`sudo chmod o-rx /usr/bin/dumpcap`  
`sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap`  
`sudo usermod -a -G wireshark $USER`  
`xhost +si:localuser:wireshark >/dev/null`  
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

# extra
setup kernel build environment\
recompile kernel\
setup geth light node sync\
osquery.io `osqueryd`  

# VirtualGL / TurboVNC

# pfSense

