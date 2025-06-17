#!/bin/bash
IFS="." read -ra ip_parts <<< "$ip"
ip_range="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.1-253"
echo "Scanning IP range: $ip_range"