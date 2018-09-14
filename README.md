# neonskies


setup movein.sh
run `bootgui.sh disable`

rm openssh keys
`dpkg-reconfigure openssh-server`
`dpkg_reconfigure tzdata`

setup swap file
run I/O benchmarking (dd_obs_test / dd_ibs_test)
setup non-priv user
/etc/ssh/sshd_config PermitRootLogin false


setup easytether on rpi
setup dhcpd on rpi
setup iptables on rpi
setup PIA VPN on rpi
setup hostapd on rpi
setup WPA Supplicant on rpi
setup DNSSEC on rpi
setup DNS caching server on rpi (use PIA DNS)
setup iptables-restore
setup cron daily restart(?)
setup unattended updates
setup fastest deb mirror (netselect)
setup deb packages
recompile kernel
setup kernel build environment

# extra
setup geth-light node
