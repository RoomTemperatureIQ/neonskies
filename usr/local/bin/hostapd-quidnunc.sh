#!/bin/sh
# placed under /usr/local/bin so user `hostapd` can execute
# chmod +x hostapd-quidnunc.sh
logger -t "$0" "hostapd event received $1 $2 $3"

hostapd_logfile=/var/log/hostapd-quidnunc.log

# Exit if file exists
if [ -e "$hostapd_logfile" ]; then
  sudo touch "$hostapd_logfile"
fi

if [ "$2" = "AP-STA-CONNECTED" ]; then
  echo "someone has connected with mac id $3 on $1" >> $hostapd_logfile
fi

if [ "$2" = "AP-STA-DISCONNECTED" ]; then
  echo "someone has disconnected with mac id $3 on $1" >> $hostapd_logfile
fi
