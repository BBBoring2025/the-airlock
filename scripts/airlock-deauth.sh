#!/bin/sh
# THE AIRLOCK v5.1.1 FORTRESS — USB Deauthorize Script
# udev tarafından çağrılır: RUN+="/usr/local/bin/airlock-deauth /sys%p/../../authorized"
# Shell olmadan doğrudan çalışır — güvenlik açığı yok.
echo 0 > "$1/authorized"
