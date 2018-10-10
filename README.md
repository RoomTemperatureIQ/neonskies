# neonskies

# .bashrc
export LANG="en_US.UTF-8"  
export PROMPT_COMMAND='history -a'  
export HISTSIZE=1000000  
export HISTFILESIZE=1000000  
export HISTCONTROL=ignoredups:ignorespace   
shopt -s cmdhist  
shopt -s histappend  

# /etc/crontab
check update certificate once a month at 00:00  
check update git repo once a day at 00:00  
0 0 1 * * /opt/letsencrypt/letsencrypt-auto renew  
0 0 * * * cd /opt/letsencrypt && git pull  
make script to check certificate expiration and adjust crontab for renew  


# /etc/fstab
```
# <file system> <mount point>   <type>  <options>       <dump>  <pass>  
proc /proc proc nodev,noexec,nosuid 0  0  
/dev/mmcblk0p1 /boot vfat defaults 0 2  
/dev/mmcblk0p2  / ext4 defaults,noatime,errors=remount-ro 0 1  
# Change this if you add a swap partition or file  
# dev/SWAP none swap sw 0 0  
```

# /etc/ntopng.conf
`-e=`  
`-i=eth0`  
`-i=wlan0`  
`-i=wlan1`  
`-w=3000`  

# /etc/resolv.conf
`chattr +i /etc/resolv.conf` # make read-only (immutable)

# /etc/hostapd/hostapd.conf

# /etc/network/interfaces

# /etc/security/limits.conf

# /etc/sudoers
`root	ALL=(ALL:ALL) ALL`  
`pi	ALL=(ALL:ALL) ALL`  

# /etc/sysctl.conf
net.ipv4.ip_forward=1  
`sysctl -w net.ipv4.ip_forward=1`  
https://wiki.archlinux.org/index.php/Sysctl  
`# use swap (0 is full RAM)`  
vm.swappiness=10

# movein.sh
`fake-hwclock`  
http://www.linuxfromscratch.org/blfs/view/svn/postlfs/initramfs.html  
`passwd`  
setup non-priv user that can `sudo`  
`adduser $user`  
`usermod -aG sudo $user`  
`/etc/ssh/sshd_config PermitRootLogin false`  
`/etc/ssh/sshd_config AllowUsers $user`  
`rm /etc/ssh/ssh_host_*`  
`dpkg-reconfigure openssh-server`  
`systemctl restart ssh.service`  
`dpkg-reconfigure tzdata`  
`update-locale`  

https://www.tecmint.com/create-a-linux-swap-file/  
`fallocate --length 2GiB /mnt/swapfile`  
`chmod 600 /mnt/swapfile`  
`mkswap /mnt/swapfile`  
`echo /mnt/swapfile none swap defaults 0 0 >> /etc/fstab`  
`nano /etc/fstab`  
`swapon /mnt/swapfile`  
`echo vm.swappiness=10 >> /etc/sysctl.conf`  
`sysctl vm.swappiness=10`  
`swapon -s`  
https://wiki.archlinux.org/index.php/swap  
https://wiki.archlinux.org/index.php/Dm-crypt/Swap_encryption  

`apt-get update`  
`apt-get install netselect-apt`  
`netselect-apt`  
`apt-get install gparted`  
`gparted`  
`resize2fs`  
`apt-get install apt-listbugs apt-listchanges arpwatch auditd bleachbit curl debsecan debian-goodies debsums firewalk htop iperf iptables-optimizer irssi locate lynis lynx macchanger netcat nethogs nload screen speedtest-cli ntopng openvpn unbound dnscrypt-proxy isc-dhcp-server hostapd wpasupplicant wireless-tools iw wvdial`  
up for chopping block: `hexchat`  
we use `debian-goodies` for `checkrestart`  
mono .net framework - https://www.mono-project.com/download/stable/#download-lin-debian  
github: dnsperf dnsperf-tcp dnsperf-tls linenum  
https://dnsprivacy.org/wiki/display/DP/Performance+Measurements  
`apt-get dist-upgrade`  
`apt-get autoremove`  
`apt-get autoclean`  
`updatedb`  
shell settings (bash_history / etc.)  

run I/O benchmarking (dd_obs_test / dd_ibs_test)  
`fdisk -l`  
https://unix.stackexchange.com/a/360080  
`blockdev --getbsz /dev/mmcblk0`  
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
setup `iptables-save` in crontab hourly  
setup `iptables-restore` on boot  
setup cron daily restart(?)  

setup `easytether` on rpi  
setup `openvpn` on rpi  
setup `unbound` (DNS caching server) on rpi (use VPN DNS as authoritative)  
setup `dnscrypt` (DNSSEC) on rpi  
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
jQuery

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

# IDA Pro

# IPTABLES
outgoing only UDP OpenVPN port (VPN Kill Switch)  
incoming - `ssh`: not 22, `unbound`: 53, `isc-dhcp-server`: 67/68, `nginx`: 80/443, `ntp`: 123, `squid`: 8080, `ntopng`: LAN side, `geth`: LAN side, `turbovnc`: LAN side (use SSH tunnel?)  
IPv6 rules  

# IRSSI
use `screen` to detach

# Let's Encrypt (SSL Certificate Issuance)
`certbot`  
https://wiki.archlinux.org/index.php/Certbot  

# NGINX
.htaccess  
wildcard forward  

# NtopNG
see flows for `iptables` rule creation

# OllyDbg

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

# OS Hardening / tweaking
https://www.askapache.com/optimize/super-speed-secrets/  
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
http://www.linuxandubuntu.com/home/top-interesting-cron-jobs-to-run-on-linux  

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

