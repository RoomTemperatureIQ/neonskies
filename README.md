# neonskies

# .bashrc
shopt -s cmdhist  
shopt -s histappend  
  export LANG="en_US.UTF-8"  
  export PROMPT_COMMAND='history -a'  
  export HISTSIZE=100000  
  export HISTFILESIZE=100000  
  export HISTCONTROL=ignoredups:erasedups:ignorespace   

# movein.sh
setup movein.sh\
rm default install openssh keys\
`dpkg-reconfigure openssh-server`  
`dpkg-reconfigure tzdata`  
`/etc/ssh/sshd_config PermitRootLogin false`  
shell settings (bash_history / etc.)

run I/O benchmarking (dd_obs_test / dd_ibs_test)\
`fdisk -l`  
`sudo umount /dev/sdX`  
`sudo dd if=/path/to/OperatingSystem.iso of=/dev/sdX bs=4M && sync`  

setup swap file\
setup non-priv user\

run `bootgui.sh disable`

# setup core services
setup deb packages (sources.list)\
setup fastest deb mirror (netselect)\
setup unattended updates\

setup iptables on rpi\
setup iptables-save in crontab\
setup iptables-restore on boot\
setup cron daily restart(?)\

setup dhcpd on rpi\
setup DNSSEC on rpi\
setup Unbound (DNS caching server) on rpi (use VPN DNS as authoritative)\
setup hostapd on rpi\
setup WPA_Supplicant on rpi\
setup OpenVPN on rpi\
setup easytether on rpi

# extra
setup kernel build environment\
recompile kernel\
setup geth light node sync\
osquery.io osqueryd
