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
KERNCONF=`which sysctl`

# VPN NIC
VPN_NIC="tun0"

# connected to Internet
WAN_NIC="wlan1"

# LAN NIC
LAN_NIC="eth0"

# WLAN NIC
WLAN_NIC="wlan0"

# server IP
HOST_IP="192.168.50.254"

# your LAN IP range
LAN_RANGE="192.168.232.0/24"

# your WLAN IP range
WLAN_RANGE="192.168.2.0/24"

# SSH port
SSH_PORT="22"

# DNS port
DNS_PORT="53"

####################
## VPN Killswitch ##
####################
# https://linuxconfig.org/how-to-create-a-vpn-killswitch-using-iptables-on-linux

# Kill IPv6
$KERNCONF -w net.ipv6.conf.all.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.default.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.eth0.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.lo.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.mon.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.tun.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.wlan0.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.wlan1.disable_ipv6=1

# toggle ICMP ping response
$KERNCONF -w net.ipv4.icmp_echo_ignore_all=0

# toggle allow forwarding
$KERNCONF -w net.ipv4.ip_forward=1
$KERNCONF -w net.ipv6.conf.all.forwarding=0
$KERNCONF -w net.ipv6.conf.default.forwarding=0
$KERNCONF -w net.ipv6.conf.eth0.forwarding=0
$KERNCONF -w net.ipv6.conf.lo.forwarding=0
$KERNCONF -w net.ipv6.conf.mon.forwarding=0
$KERNCONF -w net.ipv6.conf.tun.forwarding=0
$KERNCONF -w net.ipv6.conf.wlan0.forwarding=0
$KERNCONF -w net.ipv6.conf.wlan1.forwarding=0

# make sysctl settings persistent; commit to file
$KERNCONF -p

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

# *filter table
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP

# Forwarding
$IPT -P FORWARD ACCEPT
$IPT -A FORWARD -o $VPN_NIC -j ACCEPT
$IPT -A FORWARD -o $WAN_NIC -j ACCEPT

# *nat table
$IPT -t nat -P PREROUTING ACCEPT
$IPT -t nat -P INPUT ACCEPT
$IPT -t nat -P OUTPUT ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT
$IPT -t nat -A POSTROUTING -o $VPN_NIC -j MASQUERADE
$IPT -t nat -A POSTROUTING -o $WAN_NIC -j MASQUERADE

# Input - It's most secure to only allow inbound traffic from established or related connections. Set that up next.
$IPT -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT -p tcp -m tcp --dport $DNS_PORT -j ACCEPT
$IPT -A INPUT -p tcp -m tcp --dport $SSH_PORT -j ACCEPT
$IPT -A INPUT -i $LAN_NIC -j ACCEPT
$IPT -A INPUT -i $WLAN_NIC -j ACCEPT

# Loopback and Ping - allow the loopback interface and ping.
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A OUTPUT -o $VPN_NIC -p icmp -j ACCEPT

# LAN - It doesn't make much sense to shut down or block your LAN traffic, especially on a home network, so allow that too.
# $IPT -A OUTPUT -d 192.168.1.0/24 -j ACCEPT
$IPT -A OUTPUT -o $LAN_NIC -j ACCEPT
$IPT -A OUTPUT -o $WLAN_NIC -j ACCEPT

# DNS - For this next part, you're going to need to know the IP address of your VPN's DNS server(s).
#       If your VPN has access or your resolv.conf, you'll probably find them i there.
# DNS Server IP's: https://www.privateinternetaccess.com/helpdesk/guides/desktop/linux/linux-change-dns
#   resolver1.privateinternetaccess.com @ 209.222.18.222
#   resolver2.privateinternetaccess.com @ 209.222.18.218
# multiple IP matching: https://www.cyberciti.biz/faq/how-to-use-iptables-with-multiple-source-destination-ips-addresses/
$IPT -A OUTPUT -d 209.222.18.218,209.222.18.222 -j ACCEPT

# Allow the VPN - Of course, you need to allow the VPN itself. There are two parts to this.
# You need to allow both the service port and the interface.
# OpenVPN uses default port 1194, PIA uses port 1197
$IPT -A OUTPUT -p udp -m udp --dport 1197 -j ACCEPT
$IPT -A OUTPUT -p udp -m udp --dport 1194 -j ACCEPT
$IPT -A OUTPUT -o $VPN_NIC -j ACCEPT




# Example
#$IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 443 -j ACCEPT
#$IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 80 -j ACCEPT

#$IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 993 -j ACCEPT
#$IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 465 -j ACCEPT

# $IPT -A OUTPUT -p udp -m multiport --dports 53,80,110,443,501,502,1194,1197,1198,8080,9201 -j ACCEPT
# $IPT -A OUTPUT -p tcp -m multiport --dports 53,80,110,443,501,502,1194,1197,1198,8080,9201 -j ACCEPT
