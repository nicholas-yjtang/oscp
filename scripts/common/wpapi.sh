#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
CONFIGDIR=$SCRIPTDIR/../../config
wpscan_api=$(cat $CONFIGDIR/wpscan_api.txt)