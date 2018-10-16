#!/bin/sh

### Modified from:
### http://sharadchhetri.com/2013/06/15/how-to-protect-from-port-scanning-and-smurf-attack-in-linux-server-by-iptables/
### https://ubuntuforums.org/showthread.php?t=1003208&p=6316875#post6316875
###
### Script is for stopping Portscanning, Nmap Scanning(Fin, Null, Xmas), Smurf Attacks, Shell brute-forcing
###
### location of iptables
IPT="/usr/sbin/iptables"

### UNTESTED ###
### add crontab job for iptables-optimizer and netfilter-persistent to save
### check if rules.v4 exists
if [ -e "/etc/iptables/rules.v4.bak" ] && [ -e "/etc/iptables/rules.v4" ]; then
    echo "iptables backup file exists, not adding cronjob (assume already installed)..."
elif [ -e "$(command -v netfilter-persistent)" ] && [ -e "$(command -v iptables-optimizer)" ]; then
    echo "/etc/iptables/rule.v4 file not found, saving current iptables rules..."
    $(command -v netfilter-persistent) save

    echo "creating iptables backup file: /etc/iptables/rule.v4.bak"
    cp /etc/iptables/rules.v4 /etc/iptables/rules.v4.bak

    echo "optimizing iptables rules..."
    $(command -v iptables-optimizer) -c
    $(command -v ip6tables-optimizer) -c

    echo "saving iptables rules..."
    $(command -v netfilter-persistent) save

    echo "creating iptables-optimizer + netfilter-persistent cron job..."
    echo "0 * * * * root $(command -v iptables-optimizer) -c && sleep 2 && $(command -v ip6tables-optimizer) -c && sleep 2 && $(command -v netfilter-persistent) save" >> /etc/crontab
fi

### location of sysctl
KERNCONF=$(command -v sysctl)

### VPN NIC
VPN_NIC="tun0"

### connected to Internet
WAN_NIC="wlan1"

### LAN NIC
LAN_NIC="eth0"

### WLAN NIC
WLAN_NIC="wlan0"

### server WAN_NIC static IP
HOST_IP="192.168.1.254"

### your WAN IP range (we act as a gateway on this subnet)
WAN_RANGE="192.168.1.0/24"

### your LAN IP range
LAN_RANGE="192.168.232.0/24"

### your WLAN IP range
WLAN_RANGE="192.168.2.0/24"

### SSH port
SSH_PORT="22"

### DNS port
DNS_PORT="53"

### DHCP port
DHCP_PORT="67"

### DHCPC port
DHCPC_PORT="68"

### set the WAN to autoconnect
nmcli device set $WAN_NIC autoconnect yes

#####################
### VPN Killswitch ##
#####################
### https://linuxconfig.org/how-to-create-a-vpn-killswitch-using-iptables-on-linux
### https://wiki.archlinux.org/index.php/sysctl
### read in sysctl settings file
$KERNCONF -p

### Kill IPv6
$KERNCONF -w net.ipv6.conf.all.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.default.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.eth0.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.lo.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.mon.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.tun.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.wlan0.disable_ipv6=1
$KERNCONF -w net.ipv6.conf.wlan1.disable_ipv6=1

### toggle ICMP ping response
$KERNCONF -w net.ipv4.icmp_echo_ignore_all=0

### toggle allow forwarding
$KERNCONF -w net.ipv4.ip_forward=1
$KERNCONF -w net.ipv6.conf.all.forwarding=0
$KERNCONF -w net.ipv6.conf.default.forwarding=0
$KERNCONF -w net.ipv6.conf.eth0.forwarding=0
$KERNCONF -w net.ipv6.conf.lo.forwarding=0
$KERNCONF -w net.ipv6.conf.mon.forwarding=0
$KERNCONF -w net.ipv6.conf.tun.forwarding=0
$KERNCONF -w net.ipv6.conf.wlan0.forwarding=0
$KERNCONF -w net.ipv6.conf.wlan1.forwarding=0

### TCP/IP stack tweaking
$KERNCONF -w net.core.somaxconn=1024
$KERNCONF -w net.core.rmem_default=1048576
$KERNCONF -w net.core.rmem_max=16777216
$KERNCONF -w net.core.wmem_default=1048576
$KERNCONF -w net.core.wmem_max=16777216
$KERNCONF -w net.core.optmem_max=65536
$KERNCONF -w net.ipv4.tcp_rmem="4096 1048576 2097152"
$KERNCONF -w net.ipv4.tcp_wmem="4096 65536 16777216"
$KERNCONF -w net.ipv4.udp_rmem_min=8192
$KERNCONF -w net.ipv4.udp_wmem_min=8192
$KERNCONF -w net.ipv4.tcp_fastopen=3
$KERNCONF -w net.ipv4.tcp_max_syn_backlog=30000
$KERNCONF -w net.ipv4.tcp_syncookies=1
$KERNCONF -w net.ipv4.tcp_max_tw_buckets=2000000
$KERNCONF -w net.ipv4.tcp_tw_reuse=1
$KERNCONF -w net.ipv4.tcp_fin_timeout=10
$KERNCONF -w net.ipv4.tcp_slow_start_after_idle=0
$KERNCONF -w net.ipv4.tcp_keepalive_time=60
$KERNCONF -w net.ipv4.tcp_keepalive_intvl=10
$KERNCONF -w net.ipv4.tcp_keepalive_probes=6
$KERNCONF -w net.ipv4.tcp_mtu_probing=1
# $KERNCONF -w net.ipv4.tcp_timestamps=0
$KERNCONF -w net.ipv4.tcp_timestamps=1
$KERNCONF -w net.ipv4.tcp_rfc1337=1

### set all these redirect settings to '0' for security
$KERNCONF -w net.ipv4.conf.all.accept_redirects=1
$KERNCONF -w net.ipv4.conf.default.accept_redirects=1
$KERNCONF -w net.ipv4.conf.all.secure_redirects=1
$KERNCONF -w net.ipv4.conf.default.secure_redirects=1
$KERNCONF -w net.ipv6.conf.all.accept_redirects=1
$KERNCONF -w net.ipv6.conf.default.accept_redirects=1
$KERNCONF -w net.ipv4.conf.all.send_redirects=1
$KERNCONF -w net.ipv4.conf.default.send_redirects=1

### Kali RPi `vm.dirty_ratio` default is '20'
$KERNCONF -w vm.dirty_ratio=10

### Kali RPi `vm.dirty_background_ratio` default is '10'
$KERNCONF -w vm.dirty_background_ratio=5

### Kali RPi `vm.vfs_cache_pressure` default is '100'
$KERNCONF -w vm.vfs_cache_pressure=50

### Accept IP source route packets (we are a router)
$KERNCONF -w net.ipv4.conf.all.accept_source_route=1
$KERNCONF -w net.ipv6.conf.all.accept_source_route=1


################################################################
### Functions previously found in netbase
###

### Uncomment the next two lines to enable Spoof protection (reverse-path filter)
### Turn on Source Address Verification in all interfaces to
### prevent some spoofing attacks
$KERNCONF -w net.ipv4.conf.default.rp_filter=1
$KERNCONF -w net.ipv4.conf.all.rp_filter=1

### Uncomment the next line to enable packet forwarding for IPv6
###  Enabling this option disables Stateless Address Autoconfiguration
###  based on Router Advertisements for this host
$KERNCONF -w net.ipv6.conf.all.forwarding=0


#####################################################################
### Additional settings - these settings can improve the network
### security of the host and prevent against some network attacks
### including spoofing attacks and man in the middle attacks through
### redirection. Some network environments, however, require that these
### settings are disabled so review and enable them as needed.
###
### Accept ICMP redirects (allow MITM attacks)
$KERNCONF -w net.ipv4.conf.all.accept_redirects=1
$KERNCONF -w net.ipv6.conf.all.accept_redirects=1
### _or_
### Accept ICMP redirects only for gateways listed in our default
### gateway list (enabled by default)
$KERNCONF -w net.ipv4.conf.all.secure_redirects=1
###
### Send ICMP redirects (we are a router)
$KERNCONF -w net.ipv4.conf.all.send_redirects=0
##
### Log Martian Packets
### packet debugging
$KERNCONF -w net.ipv4.conf.default.log_martians=1
$KERNCONF -w net.ipv4.conf.all.log_martians=1
###

#####################################################################
### Magic system request Key
### 0=disable, 1=enable all, >1 bitmask of sysrq functions
### See https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
### for what other values do
# $KERNCONF -w kernel.sysrq=438



##### Reset iptables rules
### Flush all rules: -F
### Delete all chains: -X
### Zero all packets: -Z
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -F
$IPT -X
$IPT -Z

### Jump point to LOG and ACCEPT, make a note of request (SSH, VPN)
$IPT -N LOGACCEPT
# $IPT -I LOGACCEPT -m limit --limit 2/min -j LOG --log-prefix "IPTables-FILTER-Accepted: " --log-level 4
$IPT -I LOGACCEPT -j LOG --log-prefix "IPTables-FILTER-Accepted: " --log-level 4
$IPT -A LOGACCEPT -j ACCEPT

### Jump point to LOG and DROP to blackhole connection (FTP, Telnet)
$IPT -N LOGDROP
# $IPT -I LOGDROP -m limit --limit 2/min -j LOG --log-prefix "IPTables-FILTER-Dropped: " --log-level 4
$IPT -I LOGDROP -j LOG --log-prefix "IPTables-FILTER-Dropped: " --log-level 4
$IPT -A LOGDROP -j DROP

### Jump point to LOG and REJECT
### use `--reject-with tcp-reset` for TCP RST packet to appear closed
$IPT -N LOGREJECT
# $IPT -I LOGREJECT -m limit --limit 2/min -j LOG --log-prefix "IPTables-FILTER-Rejected: " --log-level 4
$IPT -I LOGREJECT -j LOG --log-prefix "IPTables-FILTER-Rejected: " --log-level 4
# $IPT -A LOGREJECT -j REJECT --reject-with tcp-reset
### not all connections use TCP
$IPT -A LOGREJECT -j REJECT

### NAT-specific LOG versions
### Jump point to LOG and ACCEPT, make a note of request (SSH, VPN)
$IPT -t nat -N LOGACCEPT-NAT
# $IPT -t nat -I LOGACCEPT-NAT -m limit --limit 2/min -j LOG --log-prefix "IPTables-NAT-Accepted: " --log-level 4
$IPT -t nat -I LOGACCEPT-NAT -j LOG --log-prefix "IPTables-NAT-Accepted: " --log-level 4
$IPT -t nat -A LOGACCEPT-NAT -j ACCEPT

### Jump point to LOG and MASQUERADE
$IPT -t nat -N LOGMASQUERADE-NAT
# $IPT -t nat -I LOGMASQUERADE-NAT -m limit --limit 2/min -j LOG --log-prefix "IPTables-NAT-Masqueraded: " --log-level 4
$IPT -t nat -I LOGMASQUERADE-NAT -j LOG --log-prefix "IPTables-NAT-Masqueraded: " --log-level 4
$IPT -t nat -A LOGMASQUERADE-NAT -j MASQUERADE

### *filter table
$IPT -P INPUT DROP
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT DROP

### Forwarding
### jump to LOGACCEPT table for debugging
# $IPT -A FORWARD -o $VPN_NIC -j LOGACCEPT
# $IPT -A FORWARD -o $LAN_NIC -j LOGACCEPT
# $IPT -A FORWARD -o $WAN_NIC -j LOGACCEPT
# $IPT -A FORWARD -o $WLAN_NIC -j LOGACCEPT
# $IPT -A FORWARD -o lo -j LOGACCEPT
# $IPT -A FORWARD -j ACCEPT

### *nat table
$IPT -t nat -P PREROUTING ACCEPT
# $IPT -t nat -I PREROUTING -j LOGACCEPT-NAT

$IPT -t nat -P INPUT ACCEPT
# $IPT -t nat -I INPUT -j LOGACCEPT-NAT

$IPT -t nat -P OUTPUT ACCEPT
# $IPT -t nat -I OUTPUT -j LOGACCEPT-NAT

$IPT -t nat -P POSTROUTING ACCEPT
$IPT -t nat -A POSTROUTING -o $VPN_NIC -j MASQUERADE
# $IPT -t nat -A POSTROUTING -o $LAN_NIC -j LOGMASQUERADE-NAT
$IPT -t nat -A POSTROUTING -o $WAN_NIC -j LOGMASQUERADE-NAT
# $IPT -t nat -A POSTROUTING -o $WLAN_NIC -j LOGMASQUERADE-NAT
# $IPT -t nat -A POSTROUTING -o lo -j LOGMASQUERADE-NAT
# $IPT -t nat -A POSTROUTING -j LOGACCEPT-NAT

### Input - It's most secure to only allow inbound traffic from established or related connections. Set that up next.
$IPT -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

### Loopback - allow the loopback interface
$IPT -A INPUT -i lo -j ACCEPT

### LAN - allow the LAN interface
$IPT -A INPUT -i $LAN_NIC -j ACCEPT

### WLAN - allow the WLAN interface (hostapd)
$IPT -A INPUT -i $WLAN_NIC -j ACCEPT

### WAN - allow the WAN_NIC to be issued a DHCP lease
$IPT -A INPUT -i $WAN_NIC -p udp -m multiport --dports $DHCP_PORT,$DHCPC_PORT -j LOGACCEPT
$IPT -A INPUT -i $WAN_NIC -p tcp -m multiport --dports $DHCP_PORT,$DHCPC_PORT -j LOGACCEPT

### WAN - allow the WAN_NIC to accept ICMP for ping requests
$IPT -A INPUT -i $WAN_NIC -p icmp -j LOGACCEPT

### jump to LOGREJECT table for debugging
$IPT -A INPUT -j LOGREJECT

### Loopback and Ping - allow the loopback interface and ping.
$IPT -A OUTPUT -o lo -j ACCEPT
### the `$IPT -A OUTPUT -o $VPN_NIC -j LOGACCEPT` covers this case, uncomment if not using that rule (explicit port ACCEPT)
# $IPT -A OUTPUT -o $VPN_NIC -p icmp -j LOGACCEPT

### LAN - It doesn't make much sense to shut down or block your LAN traffic, especially on a home network, so allow that too.
### commented out $WAN_RANGE to prevent leaks
# $IPT -A OUTPUT -d $WAN_RANGE -j LOGACCEPT
$IPT -A OUTPUT -o $LAN_NIC -j ACCEPT
$IPT -A OUTPUT -o $WLAN_NIC -j ACCEPT

### WAN - allow the WAN_NIC to be issued a DHCP lease
$IPT -A OUTPUT -o $WAN_NIC -p udp -m multiport --dports $DHCP_PORT,$DHCPC_PORT -j LOGACCEPT
$IPT -A OUTPUT -o $WAN_NIC -p tcp -m multiport --dports $DHCP_PORT,$DHCPC_PORT -j LOGACCEPT

### WAN - allow the WAN_NIC to accept ICMP for ping requests
$IPT -A OUTPUT -o $WAN_NIC -p icmp -j LOGACCEPT

### DNS - For this next part, you're going to need to know the IP address of your VPN's DNS server(s).
###       If your VPN has access or your resolv.conf, you'll probably find them i there.
### DNS Server IP's: https://www.privateinternetaccess.com/helpdesk/guides/desktop/linux/linux-change-dns
###   resolver1.privateinternetaccess.com @ 209.222.18.222
###   resolver2.privateinternetaccess.com @ 209.222.18.218
### multiple IP matching: https://www.cyberciti.biz/faq/how-to-use-iptables-with-multiple-source-destination-ips-addresses/
### port 53 UDP/TCP, unsure for DNSSEC (explicit IP covers both cases)
$IPT -A OUTPUT -d 209.222.18.218,209.222.18.222 -j ACCEPT

### Allow the VPN - Of course, you need to allow the VPN itself. There are two parts to this.
### You need to allow both the service port and the interface.
### OpenVPN uses default port 1194, PIA uses port 1197
$IPT -A OUTPUT -p udp -m multiport --dport 1197,1194 -j ACCEPT
$IPT -A OUTPUT -o $VPN_NIC -j ACCEPT

### jump to LOGREJECT table for debugging
$IPT -A OUTPUT -j LOGREJECT




### Example
# $IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 443 -j LOGACCEPT
# $IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 80 -j LOGACCEPT

# $IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 993 -j LOGACCEPT
# $IPT -A OUTPUT -o $VPN_NIC -p tcp --dport 465 -j LOGACCEPT

# $IPT -A OUTPUT -p udp -m multiport --dports 53,80,110,443,501,502,1194,1197,1198,8080,9201 -j LOGACCEPT
# $IPT -A OUTPUT -p tcp -m multiport --dports 53,80,110,443,501,502,1194,1197,1198,8080,9201 -j LOGACCEPT

echo "saving new rules..."
$(command -v netfilter-persistent) save
