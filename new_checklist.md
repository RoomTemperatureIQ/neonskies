
- - - -

Feature | Program | Implemented | Priority | Notes |   
------------- | ------------- | ------------- | ------------- | -------------  
Optimized Disk Layout Settings | dd_obs_test.sh / dd_ibs_test.sh | [❌] | critical | http://blog.tdg5.com/tuning-dd-block-size/  
Virtual RAM | swapon | [✔] | critical | https://wiki.archlinux.org/index.php/swap  
Disk Encryption | dm-crypt + LUKS | [❌] | critical | https://wiki.archlinux.org/index.php/disk_encryption  
Virtual RAM Encryption | dm-crypt + LUKS | [❌] | critical | https://wiki.archlinux.org/index.php/Dm-crypt/Swap_encryption  
Network Device MAC Address Spoofing | udev (hotplug) | [❌] | critical | https://wiki.archlinux.org/index.php/MAC_address_spoofing  
Packet Filter "Firewall" / VPN Killswitch | iptables | [✔] | critical | https://wiki.archlinux.org/index.php/iptables  
Optimized Firewall Rules | iptables-optimizer | [✔] | critical | http://manpages.ubuntu.com/manpages/xenial/man8/iptables-optimizer.8.html  
Optimized Network Settings | sysctl | [✔] | critical | https://wiki.archlinux.org/index.php/sysctl  
Network Device Management | NetworkManager | [✔] | very high | https://wiki.archlinux.org/index.php/NetworkManager  
DNS Resolver Management Framework | openresolv | [✔] | very high | https://wiki.archlinux.org/index.php/Openresolv  
SSH Server | openssh-server | [✔] | very high | https://wiki.archlinux.org/index.php/Secure_Shell  
VPN Client/Server | openvpn  | [✔] | very high | https://docs.openvpn.net/  
Tor Support | tor  | [❌] | very high | https://wiki.archlinux.org/index.php/tor  
Internet Tethering | AziLink | [❌] | very high | https://wiki.archlinux.org/index.php/Android_tethering  
DHCP Server | isc-dhcp-server  | [✔] | high | https://wiki.debian.org/DHCP_Server  
DNS Server | unbound  | [❌] | high | https://wiki.archlinux.org/index.php/Unbound https://calomel.org/unbound_dns.html  
DNSSEC Support | dnscrypt-proxy  | [❌] | high | https://wiki.archlinux.org/index.php/Dnscrypt-proxy https://dnscrypt.info/faq/  
DNS Domain Filtering (Adblocker) | unbound | [✔] | high | https://calomel.org/unbound_dns.html https://wiki.archlinux.org/index.php/unbound#Block_advertising  
Wireless Access Point | hostapd  | [❌] | high | https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf  
802.11 Authentication (WPA2/WPA/WEP) | wpa_supplicant  | [❌] | high | https://wiki.archlinux.org/index.php/WPA_supplicant  
Network Statistics | ntopng | [❌] | high | https://www.ntop.org/guides/ntopng/index.html  
Web Server | nginx | [❌] | medium | https://docs.nginx.com/  
Web Server Certificate Issuance (HTTPS) | certbot | [❌] | medium | https://certbot.eff.org/docs/  
UPS Management | nut | [❌] | medium | https://wiki.archlinux.org/index.php/Network_UPS_Tools https://loganmarchione.com/2017/02/raspberry-pi-ups-monitor-with-nginx-web-monitoring/  
Dynamic DNS Client (DDNS) | ddclient | [❌] | medium | https://freedns.afraid.org/scripts/freedns.clients.php https://calomel.org/dyndns_org.html  
Mail Server | confidantmail | [❌] | low | https://www.confidantmail.org  
Load Balancing | haproxy | [❌] | very low | https://www.haproxy.org/#docs  
Web Caching Proxy | squid | [❌] | very low | http://www.squid-cache.org/Doc/  
HTTP Domain Filtering | squid | [❌] | very low | https://www.cyberciti.biz/faq/squid-proxy-server-block-domain-accessing-internet/  
IPv6 Network Settings | | [❌] | very low | https://www.privateinternetaccess.com/helpdesk/kb/articles/why-do-you-block-ipv6  


Script Task | Program | Implemented | Priority | Task Description | Command to be run
------------- | ------------- | ------------- | ------------- | ------------- | -------------  
install cron job | lynis | [❌] | critical | perform full system audit | $(command -v )  
install cron job | netfilter-persistent | [❌] | critical | backup and save current loaded iptables rules to file | $(command -v netfilter-persistent) save  
install cron job | iptables-optimizer | [❌] | critical | optimize iptables rules | $(command -v iptables-optimizer) -c  
install cron job | pia-nm.sh | [❌] | very high | update PIA VPN server list | $(command -v sh) /root/scripts/pia-nm.sh  
install cron job | unbound | [❌] | very high | update Unbound root.hints | $(command -v )  
install cron job | letsencrypt-auto | [❌] | very high | update Lets Encrypt server certificates | $(command -v letsencrypt-auto) renew  
install cron job | certbot | [❌] | very high | upgrade Lets Encrypt local program | $(command -v cd) /opt/letsencrypt && $(command -v git) pull  
install cron job | unbound | [❌] | high | update Unbound ad servers for filtering | $(command -v curl) -o /etc/unbound/unbound_ad_servers "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=unbound&showintro=0&startdate%5Bday%5D=&startdate%5Bmonth%5D=&startdate%5Byear%5D=&mimetype=plaintext" && sleep 2 && chown unbound:unbound /etc/unbound/unbound_ad_servers  
install cron job | tuned | [❌] | medium | evaluate performance report from tuned | $(command -v )  
install cron job | netselect-apt | [❌] | medium | update closest mirror for package repos | $(command -v netselect-apt) /path/to/dpkg/sources.list  
install cron job | make | [❌] | low | compile new kernel | $(command -v )  
install cron job | tar | [❌] | low | rotate server logs | $(command -v tar)  
install cron job | squid | [❌] | very low | update Squid ad servers for filtering | $(command -v curl) -o /etc/squid/squid_ad_servers "https://example.org/ad-servers.txt"
install cron job |  | [❌] | high |  | $(command -v )  


- - - -










