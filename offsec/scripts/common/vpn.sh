#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
CONFIGDIR=$SCRIPTDIR/../../config
if [ ! -f $CONFIGDIR/universal.ovpn ]; then
    echo "No universal.ovpn file found. Please provide a valid OpenVPN configuration file."
    exit 1
fi
sudo openvpn $CONFIGDIR/universal.ovpn
