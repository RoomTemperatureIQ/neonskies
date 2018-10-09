#!/bin/sh
# forked copy from: https://github.com/gronke/systemd-iptables/blob/master/etc/iptables/flush-iptables.sh
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
