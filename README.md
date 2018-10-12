# neonskies #
![Danger: Experimental](https://camo.githubusercontent.com/275bc882f21b154b5537b9c123a171a30de9e6aa/68747470733a2f2f7261772e6769746875622e636f6d2f63727970746f7370686572652f63727970746f7370686572652f6d61737465722f696d616765732f6578706572696d656e74616c2e706e67)

Feature | Program | Implemented | Priority | Notes |   
------------- | ------------- | ------------- | ------------- | -------------  
Virtual RAM | swapon | [✔] | critical | https://wiki.archlinux.org/index.php/swap  
Optimized Disk Layout Settings | dd_obs_test.sh / dd_ibs_test.sh | [❌] | very high | http://blog.tdg5.com/tuning-dd-block-size/  
Optimized Network Settings | sysctl | [❌] | very high | https://wiki.archlinux.org/index.php/sysctl  
Network Device Management | NetworkManager | [✔] | very high | https://wiki.archlinux.org/index.php/NetworkManager  
DNS Resolver Management Framework | openresolv | [✔] | very high | https://wiki.archlinux.org/index.php/Openresolv  
SSH Server | openssh-server | [✔] | very high | https://wiki.archlinux.org/index.php/Secure_Shell  
DHCP Server | isc-dhcp-server  | [✔] | very high | https://wiki.debian.org/DHCP_Server  
DNS Server | unbound  | [❌] | very high | https://wiki.archlinux.org/index.php/Unbound https://calomel.org/unbound_dns.html  
DNSSEC Support | dnscrypt-proxy  | [❌] | very high | https://wiki.archlinux.org/index.php/Dnscrypt-proxy https://dnscrypt.info/faq/  
Wireless Access Point | hostapd  | [✔] | very high | https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf  
802.11 Authentication (WPA2/WPA/WEP) | wpa_supplicant  | [✔] | very high | https://wiki.archlinux.org/index.php/WPA_supplicant  
Network Statistics | ntopng | [✔] | very high | https://www.ntop.org/guides/ntopng/index.html  
VPN Client/Server | openvpn  | [✔] | very high | https://docs.openvpn.net/  
Packet Filter "Firewall" / VPN Killswitch | iptables | [✔] | very high | https://wiki.archlinux.org/index.php/iptables  
Web Server | nginx | [❌] | high | https://docs.nginx.com/  
Web Server Certificate Issuance (HTTPS) | certbot | [❌] | high | https://certbot.eff.org/docs/  
Internet Tethering | AziLink | [❌] | high | https://wiki.archlinux.org/index.php/Android_tethering  
UPS Management | nut | [❌] | medium | https://wiki.archlinux.org/index.php/Network_UPS_Tools https://loganmarchione.com/2017/02/raspberry-pi-ups-monitor-with-nginx-web-monitoring/  
DNS Domain Filtering | unbound | [❌] | medium | https://calomel.org/unbound_dns.html  
Disk Encryption | dm-crypt + LUKS | [❌] | low | https://wiki.archlinux.org/index.php/disk_encryption  
Virtual RAM Encryption | dm-crypt + LUKS | [❌] | low | https://wiki.archlinux.org/index.php/Dm-crypt/Swap_encryption  
Dynamic DNS Client (DDNS) | ddclient | [❌] | very low | https://freedns.afraid.org/scripts/freedns.clients.php https://calomel.org/dyndns_org.html  
Load Balancing | haproxy | [❌] | very low | https://www.haproxy.org/#docs  
Web Caching Proxy | squid | [❌] | very low | http://www.squid-cache.org/Doc/  
HTTP Domain Filtering | squid | [❌] | very low | https://www.cyberciti.biz/faq/squid-proxy-server-block-domain-accessing-internet/  
Mail Server | confidantmail | [❌] | very low | https://www.confidantmail.org  
IPv6 Network Settings | | [❌] | very low | https://www.privateinternetaccess.com/helpdesk/kb/articles/why-do-you-block-ipv6  

- - - -

# .bashrc #
LANG="en_US.UTF-8"  
HISTSIZE=1000000  
HISTFILESIZE=2000000  
HISTCONTROL=ignoreboth  
shopt -s histappend  
shopt -s cmdhist  
shopt -s lithist  
https://unix.stackexchange.com/questions/109032/how-to-get-a-history-entry-to-properly-display-on-multiple-lines  

# /etc/crontab #
check update certificate once a month at 00:00  
check update git repo once a day at 00:00  
0 0 1 * * /opt/letsencrypt/letsencrypt-auto renew  
0 0 * * * cd /opt/letsencrypt && git pull  
make script to check certificate expiration and adjust crontab for renew  


# /etc/fstab #
```
# <file system> <mount point>   <type>  <options>       <dump>  <pass>  
proc /proc proc nodev,noexec,nosuid 0  0  
/dev/mmcblk0p1 /boot vfat defaults 0 2  
/dev/mmcblk0p2  / ext4 defaults,noatime,errors=remount-ro 0 1  
# Change this if you add a swap partition or file  
# dev/SWAP none swap sw 0 0  
```

# /etc/ntopng.conf #
`-e=`  
`-i=eth0`  
`-i=wlan0`  
`-i=wlan1`  
`-w=3000`  

# /etc/resolv.conf #
`chattr +i /etc/resolv.conf` # make read-only (immutable)

# /etc/hostapd/hostapd.conf #

# /etc/network/interfaces #

# /etc/security/limits.conf #

# /etc/sudoers #
`root	ALL=(ALL:ALL) ALL`  
`pi	ALL=(ALL:ALL) ALL`  

# /etc/sysctl.d/99-sysctl.conf #
net.ipv4.ip_forward=1  
`sysctl -w net.ipv4.ip_forward=1`  
https://wiki.archlinux.org/index.php/Sysctl  
`# use swap (0 is full RAM)`  
vm.swappiness=10

# movein.sh #
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
`timedatectl`  

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
`apt-get install apt-listbugs apt-listchanges arpwatch auditd bleachbit curl debsecan debian-goodies debsums dnstop firewalk htop iperf iptables-optimizer iptables-persistent irssi locate lynis lynx macchanger netcat nethogs nload openresolv screen speedtest-cli ntopng openvpn unbound dnscrypt-proxy isc-dhcp-server hostapd wpasupplicant wireless-tools iw wvdial`  
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

`dnstop`  
`nload -U G -u M -i 102400 -o 102400`
run I/O benchmarking (dd_obs_test / dd_ibs_test)  
`fdisk -l`  
https://unix.stackexchange.com/a/360080  
`blockdev --getbsz /dev/mmcblk0`  
`sudo umount /dev/sdX`  
`sudo dd if=/path/to/OperatingSystem.iso of=/dev/sdX bs=4M && sync`  
setup swap file  
run `bootgui.sh disable`  

# setup core services #
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

# pia-nm.sh #
https://wiki.archlinux.org/index.php/NetworkManager  
https://wiki.archlinux.org/index.php/GNOME/Keyring  
`apt-get install uuid-runtime`  
look into gnome-keyring  
password-flags  
`nmcli con up id 'VPN_Name'`  
`nmcli con down id 'VPN_Name'`  

# wireshark (tshark) #
`sudo chgrp wireshark /usr/bin/dumpcap`  
`sudo chmod o-rx /usr/bin/dumpcap`  
`sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap`  
`sudo usermod -a -G wireshark $USER`  
`xhost +si:localuser:wireshark >/dev/null`  
.xauthority  
`sudo wireshark`  
`sudo tshark`  

# Node.js (NPM) #
ethereumjs-tx  
jQuery

# FreeNode - SASL & Cloak #
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

# extra #
setup kernel build environment  
recompile kernel  

# arpwatch (ARP Poisoning) #
`arpwatch`  

# DANE DNSSEC TLS Checker #

# GETH #
setup geth light node sync  

# honeyd #

# IDA Pro #

# IPTABLES #
outgoing only UDP OpenVPN port (VPN Kill Switch) tun0  
incoming - `ssh`: not 22, `unbound`: 53, `isc-dhcp-server`: 67/68, `nginx`: 80/443, `ntp`: 123, `squid`: 8080, `ntopng`: LAN side, `geth`: LAN side, `turbovnc`: LAN side (use SSH tunnel?)  
IPv6 rules  

# IRSSI #
use `screen` to detach

# Let's Encrypt (SSL Certificate Issuance) #
`certbot`  
https://wiki.archlinux.org/index.php/Certbot  

# NGINX #
.htaccess  
wildcard forward  

# NtopNG #
see flows for `iptables` rule creation

# OllyDbg #

# OpenVPN #
block-outside-dns  

# osquery #
`osqueryd`  

# ProxyChains #

# Selenium #
https://github.com/SeleniumHQ/selenium  

# SniffDet #

# SNORT #

# SQUID #

# strongSwan #

# Tripwire #

# VirtualGL / TurboVNC #

# Visual Studio (MSFT) #
use mono for .Net Framework compatibility  

# gkeyring.py #

# youtube-dl.py #

# pfSense #

# OS Hardening / tweaking #
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

