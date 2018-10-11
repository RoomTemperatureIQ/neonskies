#!/bin/sh
#
# Modified from:
# http://sharadchhetri.com/2013/06/15/how-to-protect-from-port-scanning-and-smurf-attack-in-linux-server-by-iptables/
# https://ubuntuforums.org/showthread.php?t=1003208&p=6316875#post6316875
#
# Script is for stopping Portscanning, Nmap Scanning(Fin, Null, Xmas), Smurf Attacks, Shell brute-forcing
#
# location of iptables
IPT="/usr/sbin/iptables"

#location of sysctl
KERNCONF="/usr/sbin/sysctl"

# connected to Internet
WAN_NIC="wlan1"

# server IP
HOST_IP="192.168.50.254"

# your LAN IP range
LAN_RANGE="192.168.50.0/24"

### sysctl variables
# do something here, check current status
$KERNCONF -a | grep net.ipv

# toggle allow forwarding
$KERNCONF -w net.ipv4.ip_forward=1
#$KERNCONF -w net.ipv6.conf.default.forwarding=1
#$KERNCONF -w net.ipv6.conf.all.forwarding=1

# VPN Killswitch
# https://linuxconfig.org/how-to-create-a-vpn-killswitch-using-iptables-on-linux
$KERNCONF -w net.ipv6.conf.all.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.default.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.lo.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.eth0.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.wlan0.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.wlan1.disable_ipv6=1

# toggle ICMP ping response
#$KERNCONF -w net.ipv4.icmp_echo_ignore_all=0

# log martians
#$KERNCONF -w net.ipv4.conf.all.log_martians=1

# change port range
# $KERNCONF -w net.ipv4.ip_local_port_range="32768 60999"
# $KERNCONF -w net.ipv4.ip_unprivileged_port_start=1024

# adjust TCP/IP settings (tweak MTU or w/e)


################################
### Define all port services ###
################################

### TCP
# FTP is insecure, use SFTP or SCP
IPT_FTPDATA="20"
IPT_FTP="21"
IPT_SSH="22"
# TELNET is insecure, use SSH
IPT_TELNET="23"
IPT_SMTP="25"
IPT_HTTP="80"
IPT_POP3="110"
IPT_HTTPS="443"
IPT_VPN="1194"
IPT_NTOPNG="3000"
IPT_SQUID="8080"

# TurboVNC + VirtualGL X11-Forwarding / Wayland
IPT_VNC=""

### UDP
IPT_DNS="53"
IPT_DHCP="67"
IPT_DHCPC="68"
IPT_NTP="123"
IPT_SNMP="161"
IPT_SNMPTRAP="162"


####################
## VPN Killswitch ##
####################
# *filter table
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT DROP

# Input - It's most secure to only allow inbound traffic from established or related connections. Set that up next.
$IPT -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Loopback and Ping - allow the loopback interface and ping.
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A OUTPUT -o tun0 -p icmp -j ACCEPT

# LAN - It doesn't make much sense to shut down or block your LAN traffic, especially on a home network, so allow that too.
$IPT -A OUTPUT -d 192.168.1.0/24 -j ACCEPT

# DNS - For this next part, you're going to need to know the IP address of your VPN's DNS server(s).
#       If your VPN has access or your resolv.conf, you'll probably find them i there.
# DNS Server IP's: https://www.privateinternetaccess.com/helpdesk/guides/desktop/linux/linux-change-dns
#   resolver1.privateinternetaccess.com @ 209.222.18.222
#   resolver2.privateinternetaccess.com @ 209.222.18.218
# multiple IP matching: https://www.cyberciti.biz/faq/how-to-use-iptables-with-multiple-source-destination-ips-addresses/
$IPT -A OUTPUT -d 209.222.18.218,209.222.18.222 -j ACCEPT

# Allow the VPN - Of course, you need to allow the VPN itself. There are two parts to this. 
# You need to allow both the service port and the interface.
$IPT -A OUTPUT -p udp -m udp --dport 1194 -j ACCEPT
$IPT -A OUTPUT -o tun0 -j ACCEPT

# Example
#$IPT -A OUTPUT -o tun0 -p tcp --dport 443 -j ACCEPT
#$IPT -A OUTPUT -o tun0 -p tcp --dport 80 -j ACCEPT

#$IPT -A OUTPUT -o tun0 -p tcp --dport 993 -j ACCEPT
#$IPT -A OUTPUT -o tun0 -p tcp --dport 465 -j ACCEPT





######################
## Default Policies ##
######################
# *nat table - MASQUERADING
$IPT -t nat -P PREROUTING ACCEPT
$IPT -t nat -P INPUT ACCEPT
$IPT -t nat -P OUTPUT ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT
$IPT -A POSTROUTING -o $WAN_NIC -j MASQUERADE


### *filter rules, doesn't do anything to *nat
### Default to ACCEPT to prevent SSH lockout if rules Flush
# $IPT -P INPUT ACCEPT
# $IPT -P FORWARD ACCEPT
# $IPT -P OUTPUT ACCEPT

### Reset iptables rules
# Flush all rules: -F
# Delete all chains: -X
# Zero all packets: -Z
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -F
$IPT -X
$IPT -Z

###############################
### Define all jump targets ###
###############################

# Jump point to LOG and ACCEPT, make a note of request (SSH, VPN)
$IPT -N LOGACCEPT
$IPT -I LOGACCEPT -j LOG
$IPT -A LOGACCEPT -j ACCEPT

# Jump point to LOG and DROP to blackhole connection (FTP, Telnet)
$IPT -N LOGDROP
$IPT -I LOGDROP -j LOG
$IPT -A LOGDROP -j DROP

# Jump point to LOG and REJECT with TCP RST packet to appear closed
$IPT -N LOGREJECT
$IPT -I LOGREJECT -j LOG
$IPT -A LOGREJECT -j REJECT --reject-with tcp-reset

### Match List of Spoofed IP's
# Spoofed IP's as SOURCE
$IPT -N spoofing-src
$IPT -A spoofing-src 10.0.0.0/8
$IPT -A spoofing-src 127.0.0.0/8
$IPT -A spoofing-src 169.254.0.0/16
$IPT -A spoofing-src 172.16.0.0/12
$IPT -A spoofing-src 192.168.0.0/24

# Spoofed IP's as DESTINATION
$IPT -N spoofing-dst
$IPT -A spoofing-dst 239.255.255.0/24
$IPT -A spoofing-dst 255.255.255.255

# Spoofed IP's as SOURCE and DESTINATION
$IPT -N spoofing-both
$IPT -A spoofing-both 0.0.0.0/8
$IPT -A spoofing-both 224.0.0.0/4
$IPT -A spoofing-both 240.0.0.0/5

### Blacklist
$IPT -N blacklist
$IPT -A blacklist -m recent --set --name blacklist --rsource
$IPT -A blacklist -j DROP

### ANTIBRUTE
$IPT -N anti_brute

# Protecting portscans
# Attacking IP will be locked for 24 hours (3600 x 24 = 86400 Seconds)
$IPT -A anti_brute -m recent --seconds 86400 --name blacklist --rcheck -j DROP

# Remove attacking IP after 24 hours
$IPT -A anti_brute -m recent --name blacklist --remove

# These rules add scanners to the portscan list, and log the attempt.
$IPT -A anti_brute -p tcp -m tcp --dport 139 -m recent --set --name blacklist -j LOGDROP

$IPT -A anti_brute -m recent --update --seconds 600 --hitcount 1 --name blacklist --rsource -j DROP
$IPT -A anti_brute -m recent --set --name counting1 --rsource
$IPT -A anti_brute -m recent --set --name counting2 --rsource
$IPT -A anti_brute -m recent --set --name counting3 --rsource
$IPT -A anti_brute -m recent --set --name counting4 --rsource
$IPT -A anti_brute -m recent --update --seconds 20 --hitcount 3 --name counting1 -j blacklist
$IPT -A anti_brute -m recent --update --seconds 200 --hitcount 15 --name counting2 -j blacklist
$IPT -A anti_brute -m recent --update --seconds 2000 --hitcount 80 --name counting3 -j blacklist
$IPT -A anti_brute -m recent --update --seconds 20000 --hitcount 400 --name counting4 -j blacklist
$IPT -A anti_brute -m recent --set --name blacklist --rsource
$IPT -A anti_brute -m recent --update --seconds 3600 --hitcount 5 --name blacklist --rsource -j LOGDROP
$IPT -A anti-brute -j ACCEPT


#########################
### Listening Service ###
#########################

### TCP Services
$IPT -N tcp_packets
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_SSH -m state --state NEW -j anti_brute
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_TELNET -m state --state NEW -j anti_brute
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_FTPDATA -j LOGDROP
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_FTP -j LOGDROP
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_SMTP -j ACCEPT
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_HTTP -j ACCEPT
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_POP3 -j ACCEPT
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_HTTPS -j ACCEPT
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_VPN -j LOGACCEPT
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_NTOPNG -j LOGACCEPT
$IPT -A tcp_packets -p tcp -m tcp --dport $IPT_SQUID -j LOGACCEPT

### UDP Services
$IPT -N udp_packets
$IPT -A udp_packets -p udp -m udp --dport $IPT_DNS -j ACCEPT
$IPT -A udp_packets -p udp -m udp --dport $IPT_DHCP -j ACCEPT
$IPT -A udp_packets -p udp -m udp --dport $IPT_DHCPC -j ACCEPT
$IPT -A udp_packets -p udp -m udp --dport $IPT_NTP -j ACCEPT
$IPT -A udp_packets -p udp -m udp --dport $IPT_SNMP -j ACCEPT
$IPT -A udp_packets -p udp -m udp --dport $IPT_SNMPTRAP -j ACCEPT


############################
### INPUT iptables Rules ###
############################

############################################
## Established connections are maintained ##
############################################
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

##############
## LoopBack ##
##############
iptables -A INPUT -i lo -j ACCEPT

### DROP invalid packets
$IPT -A INPUT -m state --state INVALID -j LOGREJECT

### DROP spoofed IP packets
$IPT -A INPUT -m set --match-set spoofing-src src -j LOGREJECT
$IPT -A INPUT -m set --match-set spoofing-dst dst -j LOGREJECT
$IPT -A INPUT -m set --match-set spoofing-both dst -j LOGREJECT
$IPT -A INPUT -m set --match-set spoofing-both src -j LOGREJECT


### Filter scanning
### use REJECT option to make port look closed; Use DROP for open/stealth.

## TCP Null Scan
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j LOGREJECT

## TCP Fin Scan
$IPT -A INPUT -p tcp --tcp-flags FIN,SYN FIN -m state --state NEW,INVALID -j LOGREJECT

## TCP Xmas Tree Scan (ALL URG,PSH,FIN)
$IPT -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j LOGREJECT

## TCP Xmas Tree Scan (ALL ALL) - backup just in case ^above^ rule doesn't catch
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j LOGREJECT

# flooding of RST packets, smurf attack Rejection
$IPT -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

######################
## BEGIN ICMP chain ##
######################
# for SMURF attack protection
$IPT -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j LOGREJECT
$IPT -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j LOGREJECT
$IPT -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT

# Allow ping means ICMP port is open (If you do not want ping replace ACCEPT with REJECT)
$IPT -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

$IPT -A INPUT -p tcp -m state --state NEW -j tcp_packets
$IPT -A INPUT -p udp -m state --state NEW -j udp_packets
$IPT -A INPUT -p icmp -m state --state NEW -j icmp_packets

# Lastly LOG and REJECT all remaining INPUT traffic
$IPT -A INPUT -j LOGREJECT




##############################
### FORWARD iptables rules ###
##############################
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state INVALID -j DROP

$IPT -A FORWARD -m recent --name blacklist --rcheck --seconds 86400 -j DROP
$IPT -A FORWARD -p tcp -m tcp --dport 139 -m recent --name blacklist --set -j LOGDROP
$IPT -A FORWARD -m recent --name blacklist --remove

## Reject Forwarding  traffic
$IPT -A FORWARD -j LOGREJECT




#############################
### OUTPUT iptables Rules ###
#############################
############################################
## Established connections are maintained ##
############################################
#$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

##############
## LoopBack ##
##############
#$IPT -A OUTPUT -o lo -j ACCEPT

#############
## Invalid ##
#############
#$IPT -A OUTPUT -m state --state INVALID -j LOGDROP

# $IPT -A OUTPUT -p tcp -m state --state NEW -j tcp_packets
# $IPT -A OUTPUT -p udp -m state --state NEW -j udp_packets
# $IPT -A OUTPUT -p icmp -m state --state NEW -j icmp_packets

# Allow pings
#$IPT -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Lastly Reject all Output traffic
#$IPT -A OUTPUT -j LOGREJECT


#EOF
