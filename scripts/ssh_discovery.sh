#!/bin/bash

echo "Executing Bash Script: $(basename $0) $*"

# get primary IP
primary_ip=$(ip route get 1 | awk '{print $NF;exit}')
if [ -n "${primary_ip}" ]; then
    echo "primary-ip=${primary_ip}"
fi

exit 0
