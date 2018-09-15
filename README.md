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
https://wiki.archlinux.org/index.php/Sysctl  

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
`apt-get install apt-listbugs apt-listchanges arpwatch auditd bleachbit checkrestart curl debsecan debsums firewalk hexchat htop iperf iptables-optimizer irssi linenum locate lynis lynx macchanger netcat nethogs nload screen speedtest-cli systemd-gui ntopng openvpn unbound dnscrypt isc-dhcp-server hostapd wpa_supplicant wireless-tools iw wvdial`  
mono .net framework - https://www.mono-project.com/download/stable/#download-lin-debian  
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

# arpwatch (ARP Poisoning)
`arpwatch`  

# DANE DNSSEC TLS Checker

# GETH
setup geth light node sync  

# honeyd

# IPTABLES
outgoing only UDP OpenVPN port (VPN Kill Switch)  
incoming - `ssh`: not 22, `unbound`: 53, `isc-dhcp-server`: 67/68, `nginx`: 80/443, `ntp`: 123, `squid`: 8080, `ntopng`: LAN side, `geth`: LAN side, `turbovnc`: LAN side (use SSH tunnel?)  
IPv6 rules  

# IRSSI
use `screen` to detach

# Let's Encrypt (SSL Certicate Issuance)
`certbot`  
https://wiki.archlinux.org/index.php/Certbot  

# NGINX
.htaccess  
wildcard forward  

# NtopNG
see flows for `iptables` rule creation

# OpenVPN
block-outside-dns  

# osquery
`osqueryd`  

# ProxyChains

# Selenium
https://github.com/SeleniumHQ/selenium  

# SniffDet

# SNORT

# SQUID

# strongSwan

# Tripwire

# VirtualGL / TurboVNC

# Visual Studio (MSFT)
use mono for .Net Framework compatibility  

# gkeyring.py

# youtube-dl.py

# pfSense

# OS Hardening
chroot  
jails  
fstab partitions mounted read-only  
chattr +a (append-only, breaks logrotate)  
chattr +i  
kernel tweaking  
runlevels  
grsecurity  
setcap  
setuid  
setgid  
ACL  
ASLR  
PaX  
PIE  
RBAC  
W^X  
wordlists - rockyou.txt  

`umask 0077`  
`db -p $PID`  
`trace -p $PID`  
`erf trace -p $PID`  
`eptyr $PID`  
TCP/IP IPID - https://nmap.org/presentations/CanSecWest03/CD_Content/idlescan_paper/idlescan.html  
TCP/IP Fingerprinting - https://nmap.org/book/osdetect-methods.html  
https://wiki.archlinux.org/index.php/security  
https://wiki.gentoo.org/wiki/Hardened_Gentoo  
https://wiki.gentoo.org/wiki/Hardened/Grsecurity2_Quickstart  
https://hardenedbsd.org/~shawn/hbsd_handbook/book.html#hardenedbsd  
https://web.archive.org/web/20140220055801/http://crunchbang.org:80/forums/viewtopic.php?id=24722  
https://www.ibm.com/developerworks/linux/tutorials/l-harden-server/index.html  
https://github.com/lfit/itpol/blob/master/linux-workstation-security.md  
https://debian-handbook.info/browse/stable/  
https://kali.training/  
https://www.vulnhub.com/  
https://www.pjrc.com/teensy/  
https://www.pentesteracademy.com/ (used to be SecurityTube.net)  
https://www.root-me.org/en/Challenges/  
http://scanme.nmap.org/  
VX Heavens

https://spritesmods.com/?art=hddhack  
http://3564020356.org/  
https://web.archive.org/web/20131023172320/http://0x41414141.com:80/  
https://ctftime.org/  
https://ctf365.com/  
https://www.root-me.org/en/Capture-The-Flag/  
https://www.hackthissite.org/  
http://overthewire.org/wargames/  
https://www.hacking-lab.com/index.html  
http://pwnable.kr/  
http://io.netgarage.org/  
http://smashthestack.org/  
https://microcorruption.com/login  
http://reversing.kr/index.php  
https://w3challs.com/  
https://pwn0.com/  
https://exploit-exercises.com/  
https://ringzer0team.com/  
https://www.hellboundhackers.org/  
http://www.try2hack.nl/  
https://hack.me/  
https://www.hackthis.co.uk/  
https://www.enigmagroup.org/  
https://google-gruyere.appspot.com/  
http://www.gameofhacks.com/  
http://captf.com/practice-ctf/  
http://shell-storm.org/repo/CTF/  
http://ctf.forgottensec.com/wiki/index.php?title=Main_Page  
http://ctf.infosecinstitute.com/  
https://github.com/ethicalhack3r/DVWA  
https://github.com/bt3gl/Gray-Hacker-Resources  
http://hmwyc.org/  
https://pentesterlab.com/  
https://www.hackerslab.org/  
https://backdoor.sdslabs.co/  

