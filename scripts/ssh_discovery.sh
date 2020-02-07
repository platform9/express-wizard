#!/bin/bash

echo "Executing Bash Script: $(basename $0) $*"

# get primary IP
primary_ip=$(ip route get 1 | awk '{print $NF;exit}')
if [ -n "${primary_ip}" ]; then
    echo "primary-ip=${primary_ip}"
fi

# get interface list
netdev_dir=/sys/class/net
net_list=""
if [ -d ${netdev_dir} ]; then
    for f in ${netdev_dir}/*; do
        if_name=$(basename ${f})
        if [ -z "${net_list}" ]; then
            net_list="${if_name}"
        else
            net_list="${net_list},${if_name}"
        fi
    done
    echo "interface-list=${net_list}"
fi

exit 0
