#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
partial_ip=$1
if [[ -z "$partial_ip" ]]; then
  echo "Usage: $0 <partial_ip>"
  exit 1
fi
ip_parts=(${partial_ip//./ })
partial_ip="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}"
echo "Setting partial IP to: $partial_ip"
echo $partial_ip > $SCRIPTDIR/partial_ip.txt