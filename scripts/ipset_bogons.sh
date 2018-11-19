#! /bin/bash

# forked copy from https://gist.github.com/hwdsl2/6dce75072274abfd2781
# hwdsl2/ipset_bogons.sh

# /usr/local/sbin/fullbogons-ipv4
# BoneKracker
# Rev. 11 October 2012
# Tested with ipset 6.13

# Purpose: Periodically update an ipset used in a running firewall to block
# bogons. Bogons are addresses that nobody should be using on the public
# Internet because they are either private, not to be assigned, or have
# not yet been assigned.
#
# Notes: Call this from crontab. Feed updated every 4 hours.

target="http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
# Alternative source: https://files.pfsense.org/lists/fullbogons-ipv4.txt
target2="https://files.pfsense.org/lists/fullbogons-ipv4.txt"
ipset_params="hash:net"

filename=$(basename ${target})
firewall_ipset=${filename%.*}           # ipset will be filename minus ext
data_dir="/var/tmp/${firewall_ipset}"   # data directory will be same
temp_data_dir1="/var/tmp/${firewall_ipset}"   # data directory will be same
data_file="${data_dir}/${filename}"

filename2=$(basename ${target2})
firewall_ipset2=${filename2%.*}           # ipset will be filename minus ext
data_dir2="/var/tmp/${firewall_ipset2}"   # data directory will be same
temp_data_dir2="/var/tmp/${firewall_ipset2}_temp2"   # data directory will be same
data_file2="${data_dir2}/${filename2}"

# if data directory does not exist, create it
mkdir -pm 0750 ${data_dir}
mkdir -pm 0750 ${temp_data_dir1}
mkdir -pm 0750 ${temp_data_dir2}

# function to get modification time of the file in log-friendly format
get_timestamp() {
    date -r $1 +%m/%d' '%R
}

# file modification time on server is preserved during wget download
[ -w ${data_file} ] && old_timestamp=$(get_timestamp ${data_file})

# fetch file only if newer than the version we already have
wget -qNP ${temp_data_dir1} ${target}

[ -w ${data_file2} ] && old_timestamp2=$(get_timestamp ${data_file2})
wget -qNP ${temp_data_dir2} ${target2}

echo ${temp_data_dir1}
echo ${temp_data_dir2}

echo ${target}
echo ${target2}

if [ "$?" -ne "0" ]; then
    logger -p cron.err "IPSet: ${firewall_ipset} wget failed."
    exit 1
fi

timestamp=$(get_timestamp ${data_file})
timestamp2=$(get_timestamp ${data_file2})

# compare timestamps because wget returns success even if no newer file
if [ "${timestamp}" != "${old_timestamp}" ] || [ "${timestamp2}" != "${old_timestamp2}" ]; then

    cat "${temp_data_dir}/${filename}" >> "${data_file}_combined"
    cat "${temp_data_dir2}/${filename2}" >> "${data_file}_combined"
    sort -u -o ${data_file} "${data_file}_combined"
    
    temp_ipset="${firewall_ipset}_temp"
    ipset create ${temp_ipset} ${ipset_params}

    #sed -i '/^#/d' ${data_file}            # strip comments
    sed -ri '/^[#< \t]|^$/d' ${data_file}   # occasionally the file has been xhtml

    while read network; do
        ipset add ${temp_ipset} ${network}
    done < ${data_file}

    # if ipset does not exist, create it
    ipset create -exist ${firewall_ipset} ${ipset_params}

    # swap the temp ipset for the live one
    ipset swap ${temp_ipset} ${firewall_ipset}
    ipset destroy ${temp_ipset}

    # log the file modification time for use in minimizing lag in cron schedule
    logger -p cron.notice "IPSet: ${firewall_ipset} updated (as of: ${timestamp})."

fi 
